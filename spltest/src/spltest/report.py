"""Test reports: text for people, JSON for tools, JUnit XML for CI dashboards."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import List, TextIO

from .scoring import ExpectationResult, TestResult

_GREEN, _RED, _YELLOW, _DIM, _RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _rel(path: str) -> str:
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def describe(e: ExpectationResult) -> str:
    total = len(e.instances)
    rows = sum(i.rows for i in e.instances)
    what = "fires" if e.fires else "does not fire"
    if e.fires:
        detail = f"{e.detected}/{total} run(s) detected ({rows} row(s))"
    else:
        detail = f"{e.detected}/{total} run(s) matched" + (f" ({rows} row(s))" if rows else "")
    return f"{e.expectation.scenario} [{e.label}] {what}: {detail}"


def report_text(results: List[TestResult], out: TextIO, color: bool = False, verbose: bool = False) -> None:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    for r in results:
        status = c(_GREEN, "PASS") if r.passed else c(_RED, "FAIL")
        out.write(f"{status}  {r.test.name}  {c(_DIM, _rel(r.test.path))}\n")
        if r.error:
            out.write(f"      error: {r.error}\n")
        for e in r.expectations:
            mark = c(_GREEN, "ok") if e.passed else c(_RED, "!!")
            out.write(f"  {mark}  {describe(e)}\n")
        if not r.error:
            limit = r.test.max_unexpected
            n = len(r.unexpected_rows)
            if n or verbose:
                bad = limit is not None and n > limit
                text = f"{n} row(s) not explained by any scenario" + (
                    f" (allowed: {limit})" if limit is not None else ""
                )
                out.write(f"  {c(_RED, '!!') if bad else c(_YELLOW, '--')}  {text}\n")
                for row in r.unexpected_rows[:3]:
                    shown = {k: v for k, v in row.items() if not k.startswith("_")}
                    out.write(f"        {json.dumps(shown, ensure_ascii=False)[:160]}\n")
        for note in r.notes:
            out.write(f"      {c(_DIM, 'note: ' + note)}\n")
        if r.hints and (not r.passed or verbose):
            for hint in r.hints:
                out.write(f"      {c(_YELLOW, 'hint: ' + hint)}\n")
        if not r.passed and not r.error and r.rows == 0 and any(e.fires for e in r.expectations):
            out.write(f"      {c(_YELLOW, 'hint: the search returned no rows at all')}\n")
    passed = sum(r.passed for r in results)
    out.write(f"\n{passed}/{len(results)} test(s) passed.\n")


def report_json(results: List[TestResult], out: TextIO, **_) -> None:
    payload = []
    for r in results:
        payload.append(
            {
                "name": r.test.name,
                "path": _rel(r.test.path),
                "passed": r.passed,
                "error": r.error,
                "rows": r.rows,
                "expectations": [
                    {
                        "scenario": e.expectation.scenario,
                        "label": e.label,
                        "expected_to_fire": e.fires,
                        "passed": e.passed,
                        "runs": [{"instance": i.instance, "start": i.start, "rows": i.rows} for i in e.instances],
                    }
                    for e in r.expectations
                ],
                "unexpected_rows": r.unexpected_rows,
                "notes": r.notes,
                "hints": r.hints,
            }
        )
    json.dump(payload, out, indent=2, ensure_ascii=False)
    out.write("\n")


def write_junit(results: List[TestResult], path: str) -> None:
    suite = ET.Element(
        "testsuite",
        name="spltest",
        tests=str(len(results)),
        failures=str(sum(1 for r in results if not r.passed and not r.error)),
        errors=str(sum(1 for r in results if r.error)),
    )
    for r in results:
        case = ET.SubElement(suite, "testcase", classname=_rel(r.test.path), name=r.test.name)
        lines = [describe(e) + ("" if e.passed else "  <-- failed") for e in r.expectations]
        if r.unexpected_rows:
            lines.append(f"{len(r.unexpected_rows)} row(s) not explained by any scenario")
        lines += [f"note: {n}" for n in r.notes] + [f"hint: {h}" for h in r.hints]
        if r.error:
            ET.SubElement(case, "error", message=r.error).text = "\n".join(lines)
        elif not r.passed:
            failed = next((describe(e) for e in r.expectations if not e.passed), "too many unexplained rows")
            ET.SubElement(case, "failure", message=failed).text = "\n".join(lines)
        ET.SubElement(case, "system-out").text = "\n".join(lines)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
