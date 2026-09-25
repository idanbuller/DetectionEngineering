"""Map a Sigma logsource to a Splunk index/sourcetype/base filter and rename fields.

A mapping file (YAML) looks like:

    defaults:
      field_map: {Image: process, CommandLine: process, User: user}
    logsources:
      - match: {product: windows, category: process_creation}
        index: edr
        sourcetype: "sysmon:process"
        base: "EventCode=1"           # extra base-search terms
        field_map: {Image: process_path, CommandLine: process}
      - match: {product: linux}
        index: os
        sourcetype: linux

Matching: the most specific `match` (most keys) that fully matches the rule's logsource wins.
Field maps stack: defaults first, then the winning logsource's field_map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

from .sigma import LogSource


@dataclass
class Resolved:
    index: Optional[str]
    sourcetype: Optional[str]
    base: Optional[str]
    field_map: Dict[str, str]
    extract: Dict[str, str] = None  # alias -> dotted JSON path; when set, emit `| spath` stages

    def __post_init__(self):
        if self.extract is None:
            self.extract = {}


@dataclass
class Mapping:
    default_field_map: Dict[str, str] = field(default_factory=dict)
    default_extract: Dict[str, str] = field(default_factory=dict)
    logsources: List[dict] = field(default_factory=list)

    def resolve(self, ls: LogSource) -> Resolved:
        best = None
        best_score = -1
        for entry in self.logsources:
            match = entry.get("match") or {}
            if all(getattr(ls, k, None) == v for k, v in match.items()):
                score = len(match)
                if score > best_score:
                    best, best_score = entry, score
        field_map = dict(self.default_field_map)
        extract = dict(self.default_extract)
        if best:
            field_map.update(best.get("field_map") or {})
            extract.update(best.get("extract") or {})
            return Resolved(best.get("index"), best.get("sourcetype"), best.get("base"), field_map, extract)
        return Resolved(None, None, None, field_map, extract)

    def map_field(self, name: str, resolved: Resolved) -> str:
        return resolved.field_map.get(name, name)


def load_mapping(path: Optional[str]) -> Mapping:
    if path is None:
        return default_mapping()
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: mapping must be a mapping at the top level")
    defaults_block = data.get("defaults") or {}
    defaults = defaults_block.get("field_map") or {}
    default_extract = defaults_block.get("extract") or {}
    logsources = data.get("logsources") or []
    if not isinstance(logsources, list):
        raise ValueError(f"{path}: logsources must be a list")
    return Mapping(
        {str(k): str(v) for k, v in defaults.items()},
        {str(k): str(v) for k, v in default_extract.items()},
        logsources,
    )


def default_mapping() -> Mapping:
    """A small starter mapping for the most common Sigma logsources. Override with --mapping."""
    return Mapping(
        default_field_map={},
        logsources=[
            {
                "match": {"product": "windows", "category": "process_creation"},
                "index": "windows",
                "sourcetype": "XmlWinEventLog",
                "base": "EventCode=4688",
            },
            {
                "match": {"product": "windows", "service": "sysmon"},
                "index": "edr",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            },
            {
                "match": {"product": "windows", "service": "security"},
                "index": "windows",
                "sourcetype": "XmlWinEventLog:Security",
            },
            {"match": {"product": "windows"}, "index": "windows", "sourcetype": "XmlWinEventLog"},
            {"match": {"product": "linux"}, "index": "os", "sourcetype": "linux"},
            {"match": {"category": "proxy"}, "index": "proxy", "sourcetype": "proxy"},
            {"match": {"category": "dns"}, "index": "dns", "sourcetype": "dns"},
            {"match": {"category": "firewall"}, "index": "firewall", "sourcetype": "firewall"},
        ],
    )
