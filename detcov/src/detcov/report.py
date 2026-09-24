"""Reports: text summary, JSON, a gaps view, and an ATT&CK Navigator layer."""

from __future__ import annotations

import json
from typing import Dict, List, TextIO

from . import __version__
from .coverage import (
    AT_RISK,
    BROKEN,
    COVERED,
    NO_DATA,
    PROVEN,
    TIER_ORDER,
    UNKNOWN_DATA,
    TechniqueCoverage,
    summary,
)

_LABEL = {
    PROVEN: "proven",
    COVERED: "covered",
    UNKNOWN_DATA: "unknown data",
    AT_RISK: "at risk (stale data)",
    NO_DATA: "no data",
    BROKEN: "broken (validated miss)",
}
_COLORS = {
    PROVEN: "#1b5e20",
    COVERED: "#66bb6a",
    UNKNOWN_DATA: "#9e9e9e",
    AT_RISK: "#f9a825",
    NO_DATA: "#e65100",
    BROKEN: "#c62828",
}
_TERM = {
    PROVEN: "\033[32m",
    COVERED: "\033[32m",
    AT_RISK: "\033[33m",
    NO_DATA: "\033[31m",
    BROKEN: "\033[31m",
    UNKNOWN_DATA: "\033[90m",
}
_RESET, _DIM = "\033[0m", "\033[2m"


def report_text(coverage: List[TechniqueCoverage], out: TextIO, color: bool = False, verbose: bool = False) -> None:
    def c(tier: str, s: str) -> str:
        return f"{_TERM[tier]}{s}{_RESET}" if color else s

    counts = summary(coverage)
    total = len(coverage)
    out.write(f"Coverage over {total} technique(s):\n")
    for tier in reversed(TIER_ORDER):
        n = counts[tier]
        bar = "#" * round(30 * n / total) if total else ""
        out.write(f"  {c(tier, _LABEL[tier]):<28} {n:>4}  {c(tier, bar)}\n")

    silent = [c_ for c_ in coverage if c_.tier in (NO_DATA, AT_RISK)]
    broken = [c_ for c_ in coverage if c_.tier == BROKEN]
    if silent:
        out.write(f"\n{c(AT_RISK, 'Rules likely not firing (data problem):')}\n")
        for cov in sorted(silent, key=lambda x: x.technique):
            out.write(f"  {cov.technique:12} {_LABEL[cov.tier]:<20} {', '.join(cov.detections)[:70]}\n")
    if broken:
        out.write(f"\n{c(BROKEN, 'Rules that failed validation:')}\n")
        for cov in broken:
            out.write(f"  {cov.technique:12} {', '.join(cov.detections)[:70]}\n")
    if verbose:
        out.write("\nAll techniques:\n")
        for cov in sorted(coverage, key=lambda x: (TIER_ORDER.index(x.tier), x.technique)):
            out.write(f"  {c(cov.tier, _LABEL[cov.tier]):<28} {cov.technique:12} {cov.reason}\n")


def report_json(coverage: List[TechniqueCoverage], out: TextIO, **_) -> None:
    payload = [
        {
            "technique": c.technique,
            "tier": c.tier,
            "rule_count": c.rule_count,
            "data_status": c.data_status,
            "validated": c.validated,
            "detections": c.detections,
            "reason": c.reason,
        }
        for c in coverage
    ]
    json.dump(payload, out, indent=2)
    out.write("\n")


def navigator_layer(coverage: List[TechniqueCoverage], name: str = "detcov coverage") -> Dict:
    techniques = [
        {
            "techniqueID": c.technique,
            "color": _COLORS[c.tier],
            "enabled": True,
            "comment": f"{_LABEL[c.tier]}: {c.reason}",
            "metadata": [
                {"name": "tier", "value": c.tier},
                {"name": "rules", "value": str(c.rule_count)},
                {"name": "data", "value": c.data_status},
                {"name": "validated", "value": str(c.validated)},
            ],
        }
        for c in coverage
    ]
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": f"Coverage from detcov {__version__}: rule presence x data health x validation.",
        "techniques": techniques,
        "legendItems": [{"label": _LABEL[t], "color": _COLORS[t]} for t in reversed(TIER_ORDER)],
        "sorting": 3,
    }
