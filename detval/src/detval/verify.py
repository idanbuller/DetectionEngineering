"""After a technique runs, poll Splunk until the expected signals appear or the window closes."""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from .casespec import Check
from .splunk import parse_time

SearchFn = Callable[[str, str, str], List[Dict[str, Any]]]  # (spl, earliest, latest) -> rows


@dataclass
class CheckResult:
    check: Check
    detected: bool
    rows: int
    latency_seconds: Optional[float]  # first matching event minus execution start
    polls: int
    error: Optional[str] = None
    sample: Dict[str, Any] = field(default_factory=dict)


def _values(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    return [] if v is None else [str(v)]


def row_matches(row: Dict[str, Any], match: Dict[str, str], subs: Dict[str, str]) -> bool:
    for field_name, expected in match.items():
        for token, value in subs.items():
            expected = expected.replace("{" + token + "}", value)
        if expected not in _values(row.get(field_name)):
            return False
    return True


def verify_check(
    check: Check,
    started_at: datetime,
    search: SearchFn,
    subs: Optional[Dict[str, str]] = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleep: Callable[[float], None] = _time.sleep,
) -> CheckResult:
    """Poll `search` between started_at and the window's end until min matching rows appear."""
    subs = subs or {}
    earliest = str(int(started_at.timestamp()) - 5)
    deadline = started_at + check.settle + check.window
    if check.settle.total_seconds() > 0:
        sleep(_remaining(now(), started_at + check.settle))

    # A hard cap on iterations, so a stuck clock or a tiny poll interval can't spin forever.
    poll_s = max(check.poll.total_seconds(), 1.0)
    max_polls = int(check.window.total_seconds() / poll_s) + 2
    polls = 0
    while True:
        polls += 1
        latest = str(int(now().timestamp()) + 5)
        try:
            rows = search(check.search, earliest, latest)
        except Exception as exc:  # a bad search or an unreachable Splunk fails just this check
            return CheckResult(check, False, 0, None, polls, error=str(exc))
        matching = [r for r in rows if row_matches(r, check.match, subs)]
        if len(matching) >= check.min_rows:
            return CheckResult(
                check, True, len(matching), _latency(matching, started_at), polls, sample=_sample(matching)
            )
        if now() >= deadline or polls >= max_polls:
            return CheckResult(check, False, len(matching), None, polls, sample=_sample(matching))
        sleep(min(poll_s, _remaining(now(), deadline)))


def _remaining(now_dt: datetime, until: datetime) -> float:
    return max((until - now_dt).total_seconds(), 0.0)


def _latency(rows: List[Dict[str, Any]], started_at: datetime) -> Optional[float]:
    times = [t for t in (parse_time(r.get("_time")) for r in rows) if t is not None]
    return max(min(times) - started_at.timestamp(), 0.0) if times else None


def _sample(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not rows:
        return {}
    return {k: v for k, v in rows[0].items() if not k.startswith("_") or k == "_time"}


def elapsed(td: timedelta) -> str:
    s = int(td.total_seconds())
    return f"{s}s" if s < 60 else f"{s // 60}m{s % 60:02d}s"
