"""Configuration: .spl-lint.yml, merged with command-line flags."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import yaml

from .rules import Rule, Severity

CONFIG_NAMES = (".spl-lint.yml", ".spl-lint.yaml")
DEFAULT_YAML_KEYS = ("search", "spl", "query")


@dataclass
class Config:
    select: List[str] = field(default_factory=list)  # empty = all rules
    ignore: List[str] = field(default_factory=list)
    severity: Dict[str, Severity] = field(default_factory=dict)
    yaml_keys: List[str] = field(default_factory=lambda: list(DEFAULT_YAML_KEYS))
    exclude: List[str] = field(default_factory=list)
    fail_on: Severity = Severity.WARNING
    path: Optional[str] = None  # where the config was loaded from

    def enabled(self, rule: Rule) -> bool:
        selected = _matches(rule, self.select)
        if self.select and not selected:
            return False
        if not rule.default_enabled and not selected:
            return False
        return not _matches(rule, self.ignore)

    def severity_for(self, rule: Rule) -> Severity:
        for key in (rule.id, rule.name):
            if key.lower() in self.severity:
                return self.severity[key.lower()]
        return rule.severity


def _matches(rule: Rule, patterns: Sequence[str]) -> bool:
    """A pattern is a rule id, an id prefix (SPL2), a rule name, or a category."""
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        if rule.id.upper().startswith(p.upper()) or p.lower() in (rule.name, rule.category):
            return True
    return False


def find_config(start: str) -> Optional[str]:
    directory = os.path.abspath(start)
    while True:
        for name in CONFIG_NAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def load_config(path: Optional[str]) -> Config:
    if path is None:
        return Config()
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    known = {"select", "ignore", "severity", "yaml_keys", "exclude", "fail_on"}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"{path}: unknown option(s): {', '.join(sorted(unknown))}")
    cfg = Config(path=path)
    cfg.select = _str_list(data.get("select"), "select", path)
    cfg.ignore = _str_list(data.get("ignore"), "ignore", path)
    if "yaml_keys" in data:
        cfg.yaml_keys = _str_list(data["yaml_keys"], "yaml_keys", path)
    cfg.exclude = _str_list(data.get("exclude"), "exclude", path)
    if "fail_on" in data:
        cfg.fail_on = Severity.parse(str(data["fail_on"]))
    for key, value in (data.get("severity") or {}).items():
        cfg.severity[str(key).lower()] = Severity.parse(str(value))
    return cfg


def _str_list(value, name: str, path: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise ValueError(f"{path}: {name} must be a list")
