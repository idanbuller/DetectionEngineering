"""Turn a Sigma rule into SPL plus a detection-as-code skeleton, and judge it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from spl_lint.linter import lint_text
from spl_lint.rules import Severity

from .errors import UnsupportedSigma
from .inventory import Inventory
from .mapping import Mapping
from .render import render_spl
from .sigma import SigmaRule

CONVERTED, UNSUPPORTED, FILTERED, LINT_FAILED = "converted", "unsupported", "filtered", "lint_failed"


@dataclass
class Conversion:
    rule: SigmaRule
    status: str
    spl: Optional[str] = None
    detection: Optional[Dict[str, Any]] = None
    reason: str = ""
    notes: List[str] = field(default_factory=list)
    lint: List[str] = field(default_factory=list)


def convert_rule(
    rule: SigmaRule,
    mapping: Mapping,
    inventory: Optional[Inventory] = None,
    only_available: bool = False,
    strict_lint: bool = True,
) -> Conversion:
    resolved = mapping.resolve(rule.logsource)

    if only_available and inventory and not inventory.available(resolved.index, resolved.sourcetype):
        where = f"{resolved.index or '?'}/{resolved.sourcetype or '?'}"
        return Conversion(rule, FILTERED, reason=f"data source {where} is not in the inventory")

    try:
        spl, notes = render_spl(rule, mapping, resolved)
    except UnsupportedSigma as exc:
        return Conversion(rule, UNSUPPORTED, reason=str(exc))

    findings = lint_text(spl)
    lint_lines = [f"{f.rule_id} [{f.severity}] {f.message}" for f in findings]
    errors = [f for f in findings if f.severity >= Severity.ERROR]
    if errors and strict_lint:
        return Conversion(rule, LINT_FAILED, spl=spl, reason=errors[0].message, notes=notes, lint=lint_lines)

    return Conversion(rule, CONVERTED, spl=spl, detection=_detection(rule, spl), notes=notes, lint=lint_lines)


def _detection(rule: SigmaRule, spl: str) -> Dict[str, Any]:
    """A detection-as-code skeleton that spltest/detcov can consume."""
    det: Dict[str, Any] = {"name": rule.title, "search": spl + "\n"}
    if rule.description:
        det["description"] = rule.description
    if rule.techniques:
        det["mitre"] = rule.techniques
    if rule.level:
        det["severity"] = rule.level
    if rule.falsepositives:
        det["known_false_positives"] = rule.falsepositives
    if rule.references:
        det["references"] = rule.references
    provenance = {"source": "sigma"}
    if rule.id:
        provenance["sigma_id"] = rule.id
    if rule.author:
        provenance["sigma_author"] = rule.author
    det["provenance"] = provenance
    return det
