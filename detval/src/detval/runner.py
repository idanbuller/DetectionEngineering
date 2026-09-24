"""Orchestrate one case: execute the technique, then verify each expected signal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .casespec import Case
from .executors import EXECUTED, FAILED, SKIPPED, ExecutionResult, execute_case
from .verify import CheckResult, SearchFn, verify_check


@dataclass
class CaseResult:
    case: Case
    execution: ExecutionResult
    checks: List[CheckResult] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def executed(self) -> bool:
        return self.execution.status == EXECUTED

    @property
    def detected(self) -> bool:
        return bool(self.checks) and all(c.detected for c in self.checks)

    @property
    def status(self) -> str:
        # pass: ran (or dry-run) and every expected signal appeared
        # fail: something was expected but didn't appear
        # error: the case couldn't be evaluated
        # blocked: execution was needed but skipped, so detection can't be judged
        if self.error or self.execution.status == FAILED:
            return "error"
        if self.detected:
            return "pass"
        if self.execution.status == SKIPPED and not any(c.detected for c in self.checks):
            return "blocked"
        return "fail"


def run_case(
    case: Case,
    search: SearchFn,
    allow_execution: bool = False,
    confirm: Optional[Callable[[str], bool]] = None,
    verify: bool = True,
    **verify_kwargs,
) -> CaseResult:
    try:
        execution = execute_case(case, allow_execution=allow_execution, confirm=confirm)
    except Exception as exc:
        return CaseResult(case, ExecutionResult(FAILED, _now(), None, str(exc)), error=str(exc))

    result = CaseResult(case, execution)
    if execution.status == FAILED:
        result.error = f"execution failed: {execution.detail}"
        return result
    if not verify:
        return result

    subs = {"target": execution.target or "", "technique": case.technique}
    for check in case.expect:
        result.checks.append(verify_check(check, execution.started_at, search, subs, **verify_kwargs))
    return result


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
