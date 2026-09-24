from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .config import Config
from .parser import parse
from .rules import Finding, all_rules
from .sources import QuerySource


@dataclass
class Result:
    source: QuerySource
    finding: Finding

    @property
    def line(self) -> int:
        return self.source.position(self.finding.start)[0]

    @property
    def column(self) -> int:
        return self.source.position(self.finding.start)[1]

    @property
    def end_line(self) -> int:
        return self.source.position(max(self.finding.end - 1, self.finding.start))[0]

    @property
    def end_column(self) -> int:
        return self.source.position(max(self.finding.end - 1, self.finding.start))[1] + 1


def lint_text(text: str, config: Optional[Config] = None) -> List[Finding]:
    """Lint one query and return its findings, ordered by position."""
    config = config or Config()
    query = parse(text)
    findings: List[Finding] = []
    for rule in all_rules():
        if not config.enabled(rule):
            continue
        if query.suppressed and (
            "all" in query.suppressed or rule.id in query.suppressed or rule.name.upper() in query.suppressed
        ):
            continue
        severity = config.severity_for(rule)
        for f in rule.check(query):
            f.severity = severity
            findings.append(f)
    findings.sort(key=lambda f: (f.start, f.rule_id))
    return findings


def lint_source(source: QuerySource, config: Optional[Config] = None) -> List[Result]:
    return [Result(source, f) for f in lint_text(source.text, config)]
