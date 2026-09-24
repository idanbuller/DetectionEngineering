"""Reports: text, JSON, JUnit, and an ATT&CK Navigator layer of validated coverage."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, List, TextIO

from . import __version__
from .runner import CaseResult
from .verify import CheckResult

_C = {"pass": "\033[32m", "fail": "\033[31m", "error": "\033[31m", "blocked": "\033[33m"}
_DIM, _RESET = "\033[2m", "\033[0m"
_MARK = {"pass": "PASS", "fail": "FAIL", "error": "ERR ", "blocked": "SKIP"}


def _latency(c: CheckResult) -> str:
    if c.latency_seconds is None:
        return ""
    s = int(c.latency_seconds)
    return f" in {s}s" if s < 60 else f" in {s // 60}m{s % 60:02d}s"


def report_text(results: List[CaseResult], out: TextIO, color: bool = False, verbose: bool = False) -> None:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    for r in results:
        st = r.status
        head = c(_C.get(st, ""), _MARK[st])
        out.write(f"{head}  {r.case.technique}  {r.case.name}  {c(_DIM, r.case.path)}\n")
        out.write(f"      execute: {r.execution.status} - {r.execution.detail}\n")
        if r.execution.command and (verbose or r.execution.status != "executed"):
            out.write(f"      {c(_DIM, 'command: ' + r.execution.command)}\n")
        for note in r.execution.notes:
            out.write(f"      {c(_DIM, note)}\n")
        for chk in r.checks:
            mark = c(_C["pass"], "ok") if chk.detected else c(_C["fail"], "!!")
            detail = (
                f"{chk.rows} row(s){_latency(chk)}"
                if chk.detected
                else (chk.error or f"{chk.rows} row(s), expected {chk.check.min_rows}")
            )
            out.write(f"  {mark}  [{chk.check.kind}] {chk.check.name}: {detail}\n")
        if r.error:
            out.write(f"      {c(_C['error'], 'error: ' + r.error)}\n")
    counts = Counter(r.status for r in results)
    parts = [f"{counts[k]} {k}" for k in ("pass", "fail", "blocked", "error") if counts[k]]
    out.write(f"\n{', '.join(parts) or 'no cases'} ({len(results)} case(s)).\n")


def report_json(results: List[CaseResult], out: TextIO, **_) -> None:
    payload = []
    for r in results:
        payload.append(
            {
                "technique": r.case.technique,
                "name": r.case.name,
                "path": r.case.path,
                "status": r.status,
                "execution": {
                    "status": r.execution.status,
                    "detail": r.execution.detail,
                    "target": r.execution.target,
                    "command": r.execution.command,
                    "returncode": r.execution.returncode,
                },
                "checks": [
                    {
                        "name": c.check.name,
                        "kind": c.check.kind,
                        "detected": c.detected,
                        "rows": c.rows,
                        "latency_seconds": c.latency_seconds,
                        "polls": c.polls,
                        "error": c.error,
                    }
                    for c in r.checks
                ],
                "error": r.error,
            }
        )
    json.dump(payload, out, indent=2)
    out.write("\n")


def write_junit(results: List[CaseResult], path: str) -> None:
    suite = ET.Element(
        "testsuite",
        name="detval",
        tests=str(len(results)),
        failures=str(sum(1 for r in results if r.status == "fail")),
        errors=str(sum(1 for r in results if r.status == "error")),
        skipped=str(sum(1 for r in results if r.status == "blocked")),
    )
    for r in results:
        case = ET.SubElement(suite, "testcase", classname=r.case.technique, name=r.case.name)
        lines = [f"execute: {r.execution.status} - {r.execution.detail}"]
        lines += [
            f"[{c.check.kind}] {c.check.name}: {'detected' if c.detected else 'MISSING'} ({c.rows} rows)"
            for c in r.checks
        ]
        text = "\n".join(lines)
        if r.status == "error":
            ET.SubElement(case, "error", message=r.error or "error").text = text
        elif r.status == "fail":
            missing = next((c.check.name for c in r.checks if not c.detected), "signal missing")
            ET.SubElement(case, "failure", message=f"not detected: {missing}").text = text
        elif r.status == "blocked":
            ET.SubElement(case, "skipped", message=r.execution.detail)
        ET.SubElement(case, "system-out").text = text
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


_LAYER_COLORS = {"pass": "#2e7d32", "fail": "#c62828", "blocked": "#f9a825", "error": "#6a1b9a"}


def navigator_layer(results: List[CaseResult], name: str = "detval coverage") -> Dict:
    """An ATT&CK Navigator layer: each tested technique colored by its validation status.

    pass = detection proven end to end; fail = executed but not detected;
    blocked = not executed; error = could not evaluate.
    """
    by_technique: Dict[str, List[CaseResult]] = {}
    for r in results:
        by_technique.setdefault(r.case.technique, []).append(r)

    order = {"error": 0, "fail": 1, "blocked": 2, "pass": 3}
    techniques = []
    for tech, group in sorted(by_technique.items()):
        worst = min(group, key=lambda r: order[r.status]).status  # worst status wins
        detected = sum(1 for r in group if r.status == "pass")
        techniques.append(
            {
                "techniqueID": tech,
                "color": _LAYER_COLORS[worst],
                "comment": f"detval: {detected}/{len(group)} case(s) validated",
                "metadata": [{"name": "status", "value": worst}, {"name": "cases", "value": str(len(group))}],
            }
        )
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": f"Detection validation results from detval {__version__}.",
        "techniques": techniques,
        "legendItems": [{"label": k, "color": v} for k, v in _LAYER_COLORS.items()],
        "gradient": {"colors": ["#c62828", "#2e7d32"], "minValue": 0, "maxValue": 1},
    }
