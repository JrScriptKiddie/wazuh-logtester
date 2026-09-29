#!/usr/bin/env python3
"""Экзамен L2 (Alert Fatigue + LOLBAS): автогрейдер 0–100.

Что делает:
  1. Прогоняет 1000 событий exam_dataset.json и 30 unit-кейсов test_suite.json
     через wazuh-logtester (текущие правила в manager — правила аналитика).
  2. Считает рубрику:
       FP Suppression  25 — 0 алертов на 950 легитимных событий И сохранённый
                            детект 100250 (3 blind-spot кейса); >=5% алертов -> 0.
       LOLBAS Detection 30 — покрытие 50 атак (certutil/rundll32/mshta/regsvr32).
       Evasion         25 — 17 edge-кейсов (в датасете + suite): регистр,
                            кавычки/пробелы, relative path, UNC/WebDAV, ординалы.
       XML/Architecture 10 — синтаксис, иерархия if_sid, MITRE-теги, запреты.
       Analyst Report  10 — ANALYST_REPORT.md (риски, обоснование, MITRE).
       PASSED при >= 80.

Запуск (из корня wazuh-logtester), стек должен быть поднят с правилами аналитика:

    docker compose -f docker/docker-compose.yml \
      -f exam/l2-detection/docker/compose.exam.yml up -d manager

    docker compose -f docker/docker-compose.yml \
      -f exam/l2-detection/docker/compose.exam.yml \
      run --rm --entrypoint python3 runner /exam/tests/grade_exam.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

EXAM_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = EXAM_ROOT / "test_dataset" / "exam_dataset.json"
SUITE_PATH = EXAM_ROOT / "test_dataset" / "test_suite.json"
RULES_PATH = EXAM_ROOT / "rules" / "local_rules.xml"
REPORT_PATH = EXAM_ROOT / "ANALYST_REPORT.md"

PASS_THRESHOLD = 80
FP_TOLERANCE = 0.05
BLINDSPOT_EXPECTED = 3

FAMILIES = ("certutil", "rundll32", "mshta", "regsvr32")


class Palette:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"


def _paint(enabled: bool, code: str, text: str) -> str:
    return f"{code}{text}{Palette.RESET}" if enabled else text


def _rule_id(actual) -> str | None:
    if not isinstance(actual, dict):
        return None
    rule = (actual.get("output") or {}).get("rule") if isinstance(actual.get("output"), dict) else None
    if isinstance(rule, dict) and rule.get("id") is not None:
        return str(rule["id"])
    return None


def _rule_level(actual) -> int | None:
    if not isinstance(actual, dict):
        return None
    output = actual.get("output")
    rule = output.get("rule") if isinstance(output, dict) else None
    if isinstance(rule, dict):
        try:
            return int(rule.get("level"))
        except (TypeError, ValueError):
            return None
    return None


def _alert(actual) -> bool:
    return bool(actual.get("alert")) if isinstance(actual, dict) else False


def _run_dataset(path: Path, socket: str | None):
    from wlogtest.client import LogtestClient, LogtestTransportError
    from wlogtest.dataset import load_dataset
    from wlogtest.runner import DatasetRunner

    try:
        dataset = load_dataset(str(path))
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"error: не удалось загрузить {path}: {exc}")

    client = LogtestClient(socket_path=socket)
    try:
        report = DatasetRunner(client, dataset).run()
    except LogtestTransportError as exc:
        sys.exit(
            f"error: нет соединения с logtest ({exc}).\n"
            "Поднимите manager: docker compose ... up -d manager"
        )
    finally:
        client.close()
    return dataset, report


def _raw_tests(path: Path) -> list:
    """Сырые тест-кейсы (с мета-полями category/evasion/expected_rule_id)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [t for t in raw["tests"] if not t.get("skip", False)]


def _pairs(path: Path, report) -> list:
    """[(meta, actual)] — порядок совпадает с DatasetRunner (skip отфильтрован)."""
    metas = _raw_tests(path)
    results = report.results
    if len(metas) != len(results):
        sys.exit(f"error: {path.name}: тестов {len(metas)}, результатов {len(results)}")
    return [(meta, res.verdict.actual or {}) for meta, res in zip(metas, results)]


def _detected(meta: dict, actual: dict) -> bool:
    expected = meta.get("expected_rule_id")
    return bool(_alert(actual) and expected is not None and _rule_id(actual) == str(expected))


def grade_fp(noise_pairs: list, blindspot_pairs: list) -> dict:
    fp = [meta for meta, actual in noise_pairs if _alert(actual) or (_rule_level(actual) or 0) > 0]
    fp_pct = len(fp) / len(noise_pairs) if noise_pairs else 1.0
    blind_ok = sum(1 for meta, actual in blindspot_pairs if _detected(meta, actual))
    blind_ratio = (blind_ok / len(blindspot_pairs)) if blindspot_pairs else 1.0
    factor = max(0.0, 1.0 - fp_pct / FP_TOLERANCE)
    return {
        "score": 25.0 * factor * blind_ratio,
        "fp": len(fp),
        "total": len(noise_pairs),
        "fp_pct": fp_pct,
        "blind_ok": blind_ok,
        "blind_total": len(blindspot_pairs),
    }


def grade_detection(pairs: list) -> dict:
    attacks = [(meta, actual) for meta, actual in pairs if meta.get("category") == "attack"]
    ok = [meta for meta, actual in attacks if _detected(meta, actual)]
    by_family = {fam: [0, 0] for fam in FAMILIES}
    for meta, actual in attacks:
        fam = meta.get("attack")
        if fam in by_family:
            by_family[fam][1] += 1
            if _detected(meta, actual):
                by_family[fam][0] += 1
    return {
        "score": 30.0 * (len(ok) / len(attacks)) if attacks else 0.0,
        "detected": len(ok),
        "total": len(attacks),
        "by_family": by_family,
    }


def grade_evasion(dataset_pairs: list, suite_pairs: list) -> dict:
    evasion = [
        (meta, actual)
        for meta, actual in dataset_pairs + suite_pairs
        if meta.get("evasion") is True
    ]
    ok = sum(1 for meta, actual in evasion if _detected(meta, actual))
    return {
        "score": 25.0 * (ok / len(evasion)) if evasion else 0.0,
        "detected": ok,
        "total": len(evasion),
    }


def grade_xml(path: Path) -> dict:
    score = 0.0
    notes = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return {"score": 0.0, "notes": [f"XML не читается/не парсится: {exc}"]}
    score += 2.0
    notes.append("XML парсится (+2)")

    rules = {r.get("id"): r for r in root.iter("rule") if r.get("id")}
    needed = ("100801", "100802", "100803", "100804")
    present = []
    for rule_id in needed:
        rule = rules.get(rule_id)
        if rule is None:
            continue
        try:
            level = int(rule.get("level") or 0)
        except ValueError:
            level = 0
        if level >= 8 and rule.find("if_sid") is not None:
            present.append(rule_id)
    score += 3.0 * len(present) / len(needed)
    notes.append(f"детекты 100801–100804 (уровень + if_sid): {len(present)}/4 (+{3.0 * len(present) / len(needed):.1f})")

    mitre_ok = sum(1 for rule_id in present if rules[rule_id].find("mitre/id") is not None)
    score += 2.0 * mitre_ok / len(needed)
    notes.append(f"MITRE-теги у детектов: {mitre_ok}/4 (+{2.0 * mitre_ok / len(needed):.1f})")

    desc_ok = sum(
        1
        for rule_id in present
        if (rules[rule_id].findtext("description") or "").strip()
        and (rules[rule_id].findtext("group") or "").strip()
    )
    score += 1.0 * desc_ok / len(needed)
    notes.append(f"description + group: {desc_ok}/4 (+{1.0 * desc_ok / len(needed):.1f})")

    has_if_all = any(el.tag == "if_all" for el in root.iter())
    match_type = any(el.tag == "match" and el.get("type") for el in root.iter())
    if not has_if_all and not match_type:
        score += 2.0
        notes.append("нет запрещённых конструкций (if_all / type у match) (+2)")
    else:
        bad = []
        if has_if_all:
            bad.append("<if_all>")
        if match_type:
            bad.append('type="..." у <match>')
        notes.append(f"запрещённые конструкции: {', '.join(bad)} (+0)")
    return {"score": score, "notes": notes}


def grade_report(path: Path) -> dict:
    if not path.exists():
        return {"score": 0.0, "notes": [f"{path.name} отсутствует — 0/10"]}
    text = path.read_text(encoding="utf-8", errors="ignore")
    low = text.lower()
    checks = [
        ("содержательность (>= 600 символов)", len(text) >= 600),
        ("обоснование подавления (подавл/suppress/100251/100252)", any(
            k in low for k in ("подавл", "suppress", "100251", "100252")
        )),
        ("риски слепых зон (слеп/blind)", any(k in low for k in ("слеп", "blind"))),
        ("LOLBAS-семейства + MITRE (certutil/rundll32/mshta/regsvr32, T1105/T1140/T1218)", (
            all(f in low for f in FAMILIES)
            and any(k in low for k in ("t1105", "t1140"))
            and "t1218" in low
        )),
        ("evasion-обходы (обход/evasion/кавычк/unc/webdav/регистр)", any(
            k in low for k in ("обход", "evasion", "кавычк", "unc", "webdav", "регистр")
        )),
    ]
    passed = sum(1 for _, ok in checks if ok)
    notes = [f"{'✔' if ok else '✘'} {name}" for name, ok in checks]
    return {"score": 2.0 * passed, "notes": notes, "passed": passed, "total": len(checks)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Автогрейдер экзамена L2 (0–100).")
    parser.add_argument("--socket", default=None, help="путь к сокету logtest")
    parser.add_argument(
        "--rules",
        default=str(RULES_PATH),
        help="файл правил для XML-блока оценки (по умолчанию rules/local_rules.xml; "
        "при проверке эталона: /exam/solution/solution_rules.xml)",
    )
    parser.add_argument("--json", action="store_true", help="результат в JSON")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    color = not args.no_color and os.environ.get("NO_COLOR") is None and sys.stdout.isatty()

    dataset, dataset_report = _run_dataset(DATASET_PATH, args.socket)
    suite, suite_report = _run_dataset(SUITE_PATH, args.socket)
    dataset_pairs = _pairs(DATASET_PATH, dataset_report)
    suite_pairs = _pairs(SUITE_PATH, suite_report)

    noise = [(m, a) for m, a in dataset_pairs if m.get("category") == "noise"]
    blindspot = [
        (m, a)
        for m, a in suite_pairs
        if m.get("category") == "suppression" and str(m.get("expected_rule_id")) == "100250"
    ]
    fp = grade_fp(noise, blindspot)
    detection = grade_detection(dataset_pairs)
    evasion = grade_evasion(dataset_pairs, suite_pairs)
    xml = grade_xml(Path(args.rules))
    report = grade_report(REPORT_PATH)

    total = fp["score"] + detection["score"] + evasion["score"] + xml["score"] + report["score"]
    passed = total >= PASS_THRESHOLD

    if args.json:
        print(json.dumps({
            "fp_suppression": fp,
            "lolbas_detection": detection,
            "evasion": evasion,
            "xml": xml,
            "analyst_report": report,
            "total": round(total, 2),
            "passed": passed,
            "suite": suite_report.summary,
            "dataset": dataset_report.summary,
        }, ensure_ascii=False, indent=2))
        return 0 if passed else 1

    def line(label: str, score: float, max_score: float, detail: str) -> str:
        if score >= max_score - 1e-9:
            code = Palette.GREEN
        elif score > 0:
            code = Palette.YELLOW
        else:
            code = Palette.RED
        return (
            f"{label:<18} {_paint(color, code, f'{score:5.1f}/{max_score:g}')}"
            f"  {_paint(color, Palette.DIM, detail)}"
        )

    print(_paint(color, Palette.BOLD, "=== L2 DETECTION EXAM — GRADER ==="))
    print(f"rules (XML-блок): {args.rules}")
    print(f"manager должен быть запущен с правилами: {Path(args.rules).parent}")
    print()
    print(line("FP Suppression", fp["score"], 25, f"FP {fp['fp']}/{fp['total']} на шуме; blind-spot {fp['blind_ok']}/{fp['blind_total']}"))
    fam = detection["by_family"]
    fam_detail = ", ".join(f"{k} {v[0]}/{v[1]}" for k, v in fam.items())
    print(line("LOLBAS Detection", detection["score"], 30, f"{detection['detected']}/{detection['total']} ({fam_detail})"))
    print(line("Evasion", evasion["score"], 25, f"{evasion['detected']}/{evasion['total']} edge-кейсов"))
    print(line("XML/Architecture", xml["score"], 10, "; ".join(xml["notes"])))
    print(line("Analyst Report", report["score"], 10, "; ".join(report["notes"])))
    print()
    print(f"Unit-кейсы (test_suite): {suite_report.summary['passed']}/{suite_report.summary['total']} PASS")
    if dataset_report.summary["errors"] or suite_report.summary["errors"]:
        print(_paint(color, Palette.YELLOW, f"Ошибки движка: dataset={dataset_report.summary['errors']}, suite={suite_report.summary['errors']}"))
    verdict = f"{'PASSED' if passed else 'FAILED'} (SCORE: {round(total)}/100)"
    print(_paint(color, Palette.GREEN if passed else Palette.RED, _paint(color, Palette.BOLD, f"TOTAL: {total:.1f}/100 — {verdict}")))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
