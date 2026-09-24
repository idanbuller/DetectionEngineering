"""Build the dataset, compose the search, get results, score them."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from spl_lint.linter import lint_source
from spl_lint.rules import Severity
from synthlog.engine import Dataset, generate
from synthlog.outputs import makeresults_search
from synthlog.spec import load_spec, parse_duration

from .compose import Composed, compose
from .scoring import TestResult, score
from .testspec import DetectionTest

DEFAULT_MAX_EVENTS = 5000

_cache: Dict[Tuple[str, str], Dataset] = {}


def build_dataset(test: DetectionTest) -> Dataset:
    key = (test.dataset_path, str(test.background))
    if key not in _cache:
        spec = load_spec(test.dataset_path)
        if isinstance(test.background, str):
            spec.duration = parse_duration(test.background, "background")
        _cache[key] = generate(spec, include_background=test.background is not False)
    return _cache[key]


def prepare(test: DetectionTest, max_events: int = DEFAULT_MAX_EVENTS) -> Tuple[Dataset, Composed]:
    dataset = build_dataset(test)
    if test.sources:
        unknown = set(test.sources) - set(dataset.spec.sources)
        if unknown:
            raise ValueError(
                f"sources: {', '.join(sorted(unknown))} not in the dataset ({', '.join(dataset.spec.sources)})"
            )
    n = sum(len(v) for name, v in dataset.events.items() if not test.sources or name in test.sources)
    if n > max_events:
        raise ValueError(
            f"the dataset has {n} events, more than --max-events {max_events} for one inline search; "
            "use background: false or a shorter background duration"
        )
    return dataset, compose(test.search, makeresults_search(dataset, test.sources), test.macros)


def lint_hints(test: DetectionTest) -> List[str]:
    if test.source is None:
        return []
    hints = []
    for r in lint_source(test.source):
        if r.finding.severity >= Severity.WARNING:
            hints.append(f"spl-lint {r.finding.rule_id} (line {r.line}): {r.finding.message}")
    return hints


def run_test(
    test: DetectionTest,
    fetch: Callable[[str], List[Dict[str, Any]]],
    max_events: int = DEFAULT_MAX_EVENTS,
) -> TestResult:
    """fetch takes the composed search and returns result rows."""
    try:
        dataset, composed = prepare(test, max_events)
        rows = fetch(composed.search)
        result = score(test, dataset.truth, rows)
        result.notes = composed.notes
    except Exception as exc:  # report every failure as a failed test, never a crash mid-run
        result = TestResult(test=test, passed=False, error=str(exc))
    result.hints = lint_hints(test)
    return result


def score_saved(test: DetectionTest, rows: List[Dict[str, Any]], max_events: Optional[int] = None) -> TestResult:
    return run_test(test, lambda _search: rows, max_events or DEFAULT_MAX_EVENTS)
