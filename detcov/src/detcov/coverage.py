"""Merge rules, data health, and validation into one status per ATT&CK technique."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .catalog import Detection
from .health import MISSING, STALE, UNKNOWN, Health

# Coverage tiers, worst to best. The whole point is that PROVEN and COVERED are not the same,
# and that a rule sitting on dead data (NO_DATA / AT_RISK) is worse than no rule at all.
BROKEN = "broken"  # a rule exists but validation showed it did not fire
NO_DATA = "no_data"  # a rule exists but its data source has never been seen
AT_RISK = "at_risk"  # a rule exists but its data is stale -> probably silent right now
UNKNOWN_DATA = "unknown"  # a rule exists but its data can't be resolved (macro index, no health)
COVERED = "covered"  # a rule exists on healthy data, not yet validated
PROVEN = "proven"  # a rule exists on healthy data and validation showed it fires
TIER_ORDER = [BROKEN, NO_DATA, AT_RISK, UNKNOWN_DATA, COVERED, PROVEN]


@dataclass
class TechniqueCoverage:
    technique: str
    tier: str
    rule_count: int
    data_status: str
    validated: Optional[str]  # pass | fail | None
    detections: List[str] = field(default_factory=list)
    reason: str = ""


def load_detval_results(path: str) -> Dict[str, str]:
    """Map technique -> best validation status (pass beats fail) from a detval JSON report."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    best: Dict[str, str] = {}
    for item in data:
        tech = str(item.get("technique", "")).upper()
        status = item.get("status")
        result = "pass" if status == "pass" else "fail" if status in ("fail", "error") else None
        if not tech or result is None:
            continue
        if best.get(tech) != "pass":
            best[tech] = result
    return best


def build(
    detections: List[Detection],
    health: Health,
    validation: Optional[Dict[str, str]] = None,
) -> List[TechniqueCoverage]:
    validation = validation or {}
    by_technique: Dict[str, List[Detection]] = {}
    for det in detections:
        for tech in det.techniques:
            by_technique.setdefault(tech.upper(), []).append(det)
    # Techniques that were validated but have no rule in the catalog still deserve a row.
    for tech in validation:
        by_technique.setdefault(tech, [])

    coverage = []
    for tech in sorted(by_technique):
        rules = by_technique[tech]
        pairs = set().union(*(d.data_pairs for d in rules)) if rules else set()
        macro_only = bool(rules) and not pairs and any(d.uses_macro_index for d in rules)
        data_status = health.worst(pairs) if pairs else (UNKNOWN if rules else UNKNOWN)
        validated = validation.get(tech)
        tier, reason = _tier(bool(rules), data_status, macro_only, validated)
        coverage.append(
            TechniqueCoverage(
                technique=tech,
                tier=tier,
                rule_count=len(rules),
                data_status=data_status if rules else UNKNOWN,
                validated=validated,
                detections=sorted({d.name for d in rules}),
                reason=reason,
            )
        )
    return coverage


def _tier(has_rule: bool, data_status: str, macro_only: bool, validated: Optional[str]):
    if validated == "fail":
        return BROKEN, "executed in validation but the detection did not fire"
    if not has_rule:
        # only reached for a validated-pass technique with no catalog rule
        return PROVEN if validated == "pass" else UNKNOWN_DATA, "validated but no rule found in the catalog"
    if data_status == MISSING:
        return NO_DATA, "the data this rule queries has never been seen"
    if data_status == STALE:
        return AT_RISK, "the data this rule queries is stale; the rule is probably silent"
    if data_status == UNKNOWN or macro_only:
        note = (
            "index comes from a macro; data health could not be resolved"
            if macro_only
            else "no health data for this source"
        )
        return UNKNOWN_DATA, note
    if validated == "pass":
        return PROVEN, "rule on healthy data, validated firing end to end"
    return COVERED, "rule on healthy data, not yet validated"


def summary(coverage: List[TechniqueCoverage]) -> Dict[str, int]:
    counts = {tier: 0 for tier in TIER_ORDER}
    for c in coverage:
        counts[c.tier] += 1
    return counts
