"""Parse a Sigma rule into a structured form.

Only the fields the converter needs are modelled; unknown keys are ignored. See
https://sigmahq.io/docs/basics/rules.html for the full spec.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

TECHNIQUE = re.compile(r"\bt(\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


class SigmaError(ValueError):
    pass


@dataclass
class LogSource:
    product: Optional[str] = None
    category: Optional[str] = None
    service: Optional[str] = None

    def key(self) -> str:
        return "/".join(x for x in (self.product, self.category, self.service) if x) or "(none)"


@dataclass
class SigmaRule:
    path: str
    title: str
    id: Optional[str]
    description: str
    status: Optional[str]
    level: Optional[str]
    author: Optional[str]
    references: List[str]
    falsepositives: List[str]
    tags: List[str]
    logsource: LogSource
    detection: Dict[str, Any]  # selection name -> selection body; plus "condition"
    condition: str
    fields: List[str]

    @property
    def selections(self) -> Dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k != "condition"}

    @property
    def techniques(self) -> List[str]:
        found = []
        for tag in self.tags:
            m = TECHNIQUE.search(str(tag))
            if m and str(tag).lower().startswith("attack."):
                found.append("T" + m.group(1).upper())
        return sorted(set(found))


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def parse_rule(path: str, data: Dict[str, Any]) -> SigmaRule:
    if not isinstance(data, dict):
        raise SigmaError(f"{path}: not a Sigma rule (expected a mapping)")
    detection = data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaError(f"{path}: missing a detection block with a condition")
    condition = detection["condition"]
    if isinstance(condition, list):
        # An aggregated condition list means "OR of these conditions".
        condition = " or ".join(f"({c})" for c in condition)
    ls = data.get("logsource") or {}
    if not isinstance(ls, dict):
        raise SigmaError(f"{path}: logsource must be a mapping")
    return SigmaRule(
        path=path,
        title=str(data.get("title") or os.path.basename(path)),
        id=_opt(data.get("id")),
        description=str(data.get("description", "")),
        status=_opt(data.get("status")),
        level=_opt(data.get("level")),
        author=_opt(data.get("author")),
        references=_as_list(data.get("references")),
        falsepositives=_as_list(data.get("falsepositives")),
        tags=_as_list(data.get("tags")),
        logsource=LogSource(_opt(ls.get("product")), _opt(ls.get("category")), _opt(ls.get("service"))),
        detection=detection,
        condition=str(condition),
        fields=_as_list(data.get("fields")),
    )


def _opt(v) -> Optional[str]:
    return None if v is None else str(v)


def load_rules(path: str) -> List[SigmaRule]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    rules = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise SigmaError(f"{path}: invalid YAML: {exc}") from None
    # A Sigma file may hold a rule plus "action: global" collection docs; keep the ones
    # that carry their own detection block.
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("detection"), dict):
            rules.append(parse_rule(path, doc))
    if not rules:
        raise SigmaError(f"{path}: no Sigma rule with a detection block found")
    return rules


def discover(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv"))
                out += [os.path.join(root, f) for f in sorted(files) if f.endswith((".yml", ".yaml"))]
        else:
            out.append(p)
    return out
