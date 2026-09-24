from __future__ import annotations

import textwrap
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Iterator, List, Type

from ..parser import ParsedQuery


class Severity(IntEnum):
    STYLE = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    start: int
    end: int


class Rule:
    """A lint rule. Subclasses set the metadata and implement check()."""

    id: str = ""
    name: str = ""
    category: str = ""  # correctness | performance | style | syntax
    severity: Severity = Severity.WARNING
    default_enabled: bool = True  # False: runs only when selected explicitly
    summary: str = ""
    explanation: str = ""
    bad: str = ""
    good: str = ""

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        raise NotImplementedError

    def finding(self, message: str, start: int, end: int) -> Finding:
        return Finding(self.id, self.name, self.severity, message, start, end)

    @classmethod
    def doc(cls) -> str:
        return textwrap.dedent(cls.explanation).strip()


_REGISTRY: Dict[str, Type[Rule]] = {}


def register(cls: Type[Rule]) -> Type[Rule]:
    if cls.id in _REGISTRY:
        raise ValueError(f"duplicate rule id {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_rules() -> List[Rule]:
    return [_REGISTRY[k]() for k in sorted(_REGISTRY)]
