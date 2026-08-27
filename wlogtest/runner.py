from __future__ import annotations

import time
from dataclasses import dataclass, field

from wlogtest.client import LogtestError
from wlogtest.verdict import Verdict, evaluate


@dataclass
class CaseResult:
    verdict: Verdict
    session: str
    token: str


@dataclass
class RunReport:
    dataset_name: str
    results: list = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return all(result.verdict.status == "pass" for result in self.results)

    @property
    def summary(self) -> dict:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.verdict.status == "pass")
        failed = sum(1 for r in self.results if r.verdict.status == "fail")
        errors = sum(1 for r in self.results if r.verdict.status == "error")
        return {"total": total, "passed": passed, "failed": failed, "errors": errors}

    def to_dict(self) -> dict:
        return {
            "dataset": self.dataset_name,
            "summary": self.summary,
            "duration_ms": self.duration_ms,
            "results": [
                {
                    "name": result.verdict.case_name,
                    "session": result.session,
                    "token": result.token,
                    "status": result.verdict.status,
                    "error": result.verdict.error,
                    "checks": [
                        {
                            "path": check.path,
                            "expected": check.expected,
                            "actual": check.actual,
                            "matched": check.matched,
                            "reason": check.reason,
                        }
                        for check in result.verdict.checks
                    ],
                    "actual": result.verdict.actual,
                }
                for result in self.results
            ],
        }


class DatasetRunner:
    def __init__(self, client, dataset) -> None:
        self.client = client
        self.dataset = dataset

    def _best_effort_remove(self, token: str) -> None:
        if not token:
            return
        try:
            self.client.remove_session(token)
        except Exception:
            pass

    def run(self) -> RunReport:
        start = time.monotonic()
        results = []
        session_tokens = {}
        for index, case in enumerate(self.dataset.tests):
            if case.skip:
                continue
            if self.dataset.session_mode == "per_test":
                session_key = f"__case_{index}"
                fresh = True
            else:
                session_key = case.session or "shared"
                fresh = False
            token = "" if fresh else session_tokens.get(session_key, "")
            try:
                data = self.client.run_log(
                    case.event,
                    location=case.location or self.dataset.default_location,
                    log_format=case.log_format or self.dataset.default_log_format,
                    token=token or None,
                )
            except LogtestError as exc:
                verdict = Verdict(case_name=case.name, status="error", error=str(exc))
                results.append(
                    CaseResult(verdict=verdict, session=session_key, token=token or "")
                )
                continue
            if not isinstance(data, dict):
                data = {}
            if fresh:
                new_token = data.get("token", "") or ""
                verdict = evaluate(case.name, case.expect, data)
                results.append(
                    CaseResult(verdict=verdict, session=session_key, token=new_token)
                )
                self._best_effort_remove(new_token)
            else:
                if not token:
                    token = data.get("token", "") or ""
                    session_tokens[session_key] = token
                verdict = evaluate(case.name, case.expect, data)
                results.append(
                    CaseResult(verdict=verdict, session=session_key, token=token or "")
                )
        for token in session_tokens.values():
            self._best_effort_remove(token)
        duration_ms = (time.monotonic() - start) * 1000.0
        return RunReport(
            dataset_name=self.dataset.name,
            results=results,
            duration_ms=duration_ms,
        )
