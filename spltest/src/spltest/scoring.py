"""Score a detection's result rows against a synthlog dataset's ground truth."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from synthlog.generators import Template

from .testspec import DetectionTest, Expectation


@dataclass
class InstanceResult:
    instance: int
    start: str
    rows: int  # result rows attributed to this run


@dataclass
class ExpectationResult:
    expectation: Expectation
    fires: bool  # what was expected
    label: str
    instances: List[InstanceResult]
    passed: bool

    @property
    def detected(self) -> int:
        return sum(1 for i in self.instances if i.rows)


@dataclass
class TestResult:
    test: DetectionTest
    passed: bool
    rows: int = 0
    expectations: List[ExpectationResult] = field(default_factory=list)
    unexpected_rows: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    hints: List[str] = field(default_factory=list)


def _values(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    return [] if v is None else [str(v)]


def _entity_lookup(entities: Dict[str, Dict[str, Any]]):
    def lookup(name: str, spec: Optional[str]) -> str:
        role, _, attr = name.partition(".")
        if role not in entities or attr not in entities[role]:
            raise KeyError(name)
        value = entities[role][attr]
        return format(value, spec) if spec else str(value)

    return lookup


TIME_FIELDS = ("_time", "firstTime", "lastTime", "first_seen", "last_seen", "earliest", "latest")
TIME_SLACK_SECONDS = 120
_SPLUNK_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s*(?:UTC|Z|\+00:?00))?$")


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds from an epoch number/string, ISO time, or Splunk's display format (UTC)."""
    for v in _values(value):
        v = v.strip()
        try:
            x = float(v)
        except ValueError:
            m = _SPLUNK_TIME.match(v)
            if not m:
                continue
            dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)[:15]}")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        if 1e9 <= x < 1e11:
            return x
    return None


def _iso_epoch(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def row_in_window(row: Dict[str, Any], truth: Dict[str, Any]) -> bool:
    """True when the row has no time fields, or its time span overlaps the run's window."""
    times = [t for t in (parse_time(row.get(f)) for f in TIME_FIELDS) if t is not None]
    if not times:
        return True
    start = _iso_epoch(truth["start"]) - TIME_SLACK_SECONDS
    end = _iso_epoch(truth["end"]) + TIME_SLACK_SECONDS
    return min(times) <= end and max(times) >= start


def row_matches(row: Dict[str, Any], truth: Dict[str, Any], match: Dict[str, str]) -> bool:
    """With match: every listed field has the templated value. Without: any row value
    equals any entity attribute involved in the scenario run. Either way, a row that
    carries time fields must overlap the run's time window."""
    if not row_in_window(row, truth):
        return False
    entities = truth.get("entities", {})
    if match:
        lookup = _entity_lookup(entities)
        for field_name, template in match.items():
            expected = Template(template).render(lookup)
            if expected not in _values(row.get(field_name)):
                return False
        return True
    wanted = {str(v) for attrs in entities.values() for v in attrs.values() if not isinstance(v, (list, dict))}
    return any(v in wanted for value in row.values() for v in _values(value))


def check_templates(test: DetectionTest, truth: List[Dict[str, Any]]) -> None:
    """Fail early, with a clear message, on match templates that name unknown roles or attributes."""
    for exp in test.expect:
        runs = [t for t in truth if t["scenario"] == exp.scenario]
        if not runs:
            known = ", ".join(sorted({t["scenario"] for t in truth})) or "none"
            raise ValueError(f"expect: scenario {exp.scenario!r} is not in the dataset (scenarios: {known})")
        lookup = _entity_lookup(runs[0].get("entities", {}))
        for field_name, template in exp.match.items():
            try:
                Template(template).render(lookup)
            except KeyError as exc:
                roles = ", ".join(f"{r}.{a}" for r, attrs in runs[0]["entities"].items() for a in attrs) or "none"
                raise ValueError(
                    f"expect {exp.scenario}: match.{field_name} uses {{{exc.args[0]}}}, which the scenario doesn't "
                    f"bind (available: {roles})"
                ) from None


def score(test: DetectionTest, truth: List[Dict[str, Any]], rows: List[Dict[str, Any]]) -> TestResult:
    check_templates(test, truth)
    result = TestResult(test=test, passed=True, rows=len(rows))
    explained = [False] * len(rows)
    listed = {e.scenario: e for e in test.expect}

    # Attribute rows to every scenario run they match (using the test's match rules when listed).
    per_run: Dict[int, int] = {}
    for idx, run in enumerate(truth):
        exp = listed.get(run["scenario"])
        match = exp.match if exp else {}
        count = 0
        for r, row in enumerate(rows):
            if row_matches(row, run, match):
                count += 1
                explained[r] = True
        per_run[idx] = count

    for exp in test.expect:
        runs = [(i, t) for i, t in enumerate(truth) if t["scenario"] == exp.scenario]
        label = runs[0][1]["label"]
        fires = exp.fires if exp.fires is not None else label == "malicious"
        instances = [InstanceResult(t["instance"], t["start"], per_run[i]) for i, t in runs]
        hits = [bool(i.rows) for i in instances]
        if fires:
            ok = all(hits) if exp.instances == "all" else any(hits)
        else:
            ok = not any(hits) if exp.instances == "all" else not all(hits)
        result.expectations.append(ExpectationResult(exp, fires, label, instances, ok))
        result.passed = result.passed and ok

    result.unexpected_rows = [row for row, ok in zip(rows, explained) if not ok]
    if test.max_unexpected is not None and len(result.unexpected_rows) > test.max_unexpected:
        result.passed = False
    return result
