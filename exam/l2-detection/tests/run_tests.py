#!/usr/bin/env python3
"""Экзамен L2: прогон unit-кейсов (test_suite.json) через wazuh-logtester.

Запуск внутри runner-контейнера (из корня wazuh-logtester):

    docker compose -f docker/docker-compose.yml \
      -f exam/l2-detection/docker/compose.exam.yml \
      run --rm --entrypoint python3 runner /exam/tests/run_tests.py

Или на хосте из корня репозитория (нужен PYTHONPATH=. и живой сокет logtest):

    PYTHONPATH=. python3 exam/l2-detection/tests/run_tests.py

Код возврата: 0 — все кейсы PASS, 1 — есть FAIL/ERROR.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

EXAM_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = EXAM_ROOT / "test_dataset" / "test_suite.json"


def _import_wlogtest():
    try:
        from wlogtest.client import LogtestClient, LogtestTransportError
        from wlogtest.dataset import load_dataset
        from wlogtest.report import render_console, render_json
        from wlogtest.runner import DatasetRunner
    except ImportError:
        sys.exit(
            "error: пакет wlogtest не найден.\n"
            "Запускайте внутри runner-контейнера (см. докstring) или из корня\n"
            "репозитория с PYTHONPATH=."
        )
    return (
        LogtestClient,
        LogtestTransportError,
        load_dataset,
        render_console,
        render_json,
        DatasetRunner,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Прогон unit-кейсов экзамена L2 через wazuh-logtester."
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        default=str(DEFAULT_DATASET),
        help="датасет (по умолчанию test_suite.json экзамена)",
    )
    parser.add_argument("--socket", default=None, help="путь к сокету logtest")
    parser.add_argument("--json", action="store_true", help="отчёт в JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    (
        LogtestClient,
        LogtestTransportError,
        load_dataset,
        render_console,
        render_json,
        DatasetRunner,
    ) = _import_wlogtest()

    try:
        dataset = load_dataset(args.dataset)
    except Exception as exc:  # noqa: BLE001 - сообщение важнее типа
        sys.exit(f"error: не удалось загрузить датасет: {exc}")

    client = LogtestClient(socket_path=args.socket)
    try:
        report = DatasetRunner(client, dataset).run()
    except LogtestTransportError as exc:
        sys.exit(
            f"error: нет соединения с logtest ({exc}).\n"
            "Поднимите manager: docker compose ... up -d manager"
        )
    finally:
        client.close()

    print(render_json(report) if args.json else render_console(report, verbose=args.verbose))
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
