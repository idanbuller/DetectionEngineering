"""Output formats: text (default), json, sarif, github."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import List, TextIO

from . import __version__
from .linter import Result
from .rules import Severity, all_rules

_COLORS = {
    Severity.ERROR: "\033[31m",
    Severity.WARNING: "\033[33m",
    Severity.INFO: "\033[36m",
    Severity.STYLE: "\033[90m",
}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"


def _relpath(path: str) -> str:
    if path == "-":
        return "<stdin>"
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def report_text(results: List[Result], out: TextIO, color: bool, files: int, queries: int) -> None:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    for r in results:
        f = r.finding
        where = f"{_relpath(r.source.path)}:{r.line}:{r.column}"
        name = f" ({r.source.name})" if r.source.name else ""
        out.write(
            f"{c(_BOLD, where)}: {c(_COLORS[f.severity], f'{f.rule_id} [{f.severity}]')} {f.message}{c(_DIM, name)}\n"
        )
        line, col = r.source.line_text(f.start)
        width = max(1, min(f.end, f.start + len(line) - col) - f.start)
        out.write(f"    {line}\n    {' ' * col}{c(_COLORS[f.severity], '^' * width)}\n")
    counts = Counter(r.finding.severity for r in results)
    if results:
        parts = [f"{counts[s]} {s}" for s in sorted(counts, reverse=True)]
        out.write(
            f"\nFound {len(results)} issue(s) ({', '.join(parts)}) in {queries} "
            f"quer{'y' if queries == 1 else 'ies'} across {files} file(s).\n"
        )
    else:
        out.write(f"No issues in {queries} quer{'y' if queries == 1 else 'ies'} across {files} file(s).\n")


def report_json(results: List[Result], out: TextIO, **_) -> None:
    payload = [
        {
            "path": _relpath(r.source.path),
            "query_name": r.source.name,
            "line": r.line,
            "column": r.column,
            "end_line": r.end_line,
            "end_column": r.end_column,
            "rule": r.finding.rule_id,
            "name": r.finding.rule_name,
            "severity": str(r.finding.severity),
            "message": r.finding.message,
        }
        for r in results
    ]
    json.dump(payload, out, indent=2)
    out.write("\n")


_SARIF_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "note", Severity.STYLE: "note"}


def report_sarif(results: List[Result], out: TextIO, **_) -> None:
    rules = all_rules()
    index = {r.id: i for i, r in enumerate(rules)}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "spl-lint",
                        "version": __version__,
                        "informationUri": "https://github.com/idanbuller/DetectionEngineering/tree/main/spl-lint",
                        "rules": [
                            {
                                "id": r.id,
                                "name": r.name,
                                "shortDescription": {"text": r.summary},
                                "fullDescription": {"text": r.doc()},
                                "helpUri": "https://github.com/idanbuller/DetectionEngineering/blob/main/"
                                f"spl-lint/docs/rules.md#{r.id.lower()}-{r.name}",
                                "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                                "properties": {"tags": [r.category]},
                            }
                            for r in rules
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": r.finding.rule_id,
                        "ruleIndex": index[r.finding.rule_id],
                        "level": _SARIF_LEVEL[r.finding.severity],
                        "message": {"text": r.finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _relpath(r.source.path).replace(os.sep, "/")},
                                    "region": {
                                        "startLine": r.line,
                                        "startColumn": r.column,
                                        "endLine": r.end_line,
                                        "endColumn": r.end_column,
                                    },
                                }
                            }
                        ],
                    }
                    for r in results
                ],
            }
        ],
    }
    json.dump(sarif, out, indent=2)
    out.write("\n")


_GITHUB_LEVEL = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "notice",
    Severity.STYLE: "notice",
}


def _gh_escape(s: str, prop: bool = False) -> str:
    s = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def report_github(results: List[Result], out: TextIO, **_) -> None:
    """GitHub Actions workflow commands; findings appear as annotations on the PR diff."""
    for r in results:
        f = r.finding
        props = (
            f"file={_gh_escape(_relpath(r.source.path), True)},line={r.line},col={r.column},"
            f"endLine={r.end_line},title={_gh_escape(f'{f.rule_id} {f.rule_name}', True)}"
        )
        out.write(f"::{_GITHUB_LEVEL[f.severity]} {props}::{_gh_escape(f.message)}\n")


REPORTERS = {"text": report_text, "json": report_json, "sarif": report_sarif, "github": report_github}
