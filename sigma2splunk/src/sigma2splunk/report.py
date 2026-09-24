"""Summaries of a conversion run: text and JSON."""

from __future__ import annotations

import json
from collections import Counter
from typing import List, TextIO

from .convert import CONVERTED, FILTERED, LINT_FAILED, UNSUPPORTED, Conversion

_C = {CONVERTED: "\033[32m", FILTERED: "\033[90m", UNSUPPORTED: "\033[33m", LINT_FAILED: "\033[31m"}
_RESET, _DIM = "\033[0m", "\033[2m"
_LABEL = {
    CONVERTED: "converted",
    FILTERED: "filtered (no data)",
    UNSUPPORTED: "unsupported",
    LINT_FAILED: "lint failed",
}


def report_text(results: List[Conversion], out: TextIO, color: bool = False, verbose: bool = False) -> None:
    def c(status: str, s: str) -> str:
        return f"{_C[status]}{s}{_RESET}" if color else s

    counts = Counter(r.status for r in results)
    for r in results:
        if r.status == CONVERTED and not verbose:
            continue
        line = f"{c(r.status, _LABEL[r.status]):<20} {r.rule.title}"
        if r.reason:
            line += f"  {c(r.status, '- ' + r.reason)}"
        out.write(line + "\n")
        for note in r.notes:
            out.write(f"    {_dim('note: ' + note, color)}\n")
    parts = [f"{counts[k]} {_LABEL[k]}" for k in (CONVERTED, FILTERED, UNSUPPORTED, LINT_FAILED) if counts[k]]
    out.write(f"\n{', '.join(parts) or 'nothing to do'} ({len(results)} rule(s)).\n")


def _dim(s: str, color: bool) -> str:
    return f"{_DIM}{s}{_RESET}" if color else s


def report_json(results: List[Conversion], out: TextIO, **_) -> None:
    payload = [
        {
            "title": r.rule.title,
            "path": r.rule.path,
            "status": r.status,
            "techniques": r.rule.techniques,
            "spl": r.spl,
            "reason": r.reason,
            "notes": r.notes,
            "lint": r.lint,
        }
        for r in results
    ]
    json.dump(payload, out, indent=2)
    out.write("\n")
