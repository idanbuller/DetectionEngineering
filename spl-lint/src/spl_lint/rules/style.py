"""Consistency rules. Style findings never fail a run unless --fail-on style is set."""

from __future__ import annotations

from typing import Iterator

from ..parser import WORD, ParsedQuery
from .base import Finding, Rule, Severity, register


@register
class UppercaseCommand(Rule):
    id = "SPL301"
    name = "uppercase-keyword"
    category = "style"
    severity = Severity.STYLE
    default_enabled = False
    summary = "Commands and clause keywords (by, as, over, output) are written in lowercase."
    explanation = """
        SPL command names and clause keywords are case-insensitive, so this is
        purely about consistency: a repository where every query writes
        `stats count by user` is easier to read, grep and diff than one that
        mixes `STATS`, `Stats` and `stats`. This rule is off by default;
        enable it with `--select SPL301` or `select: [style]`. Boolean operators in search
        (AND, OR, NOT, IN) are not affected; they must stay uppercase.
    """
    bad = "index=auth | STATS count BY user"
    good = "index=auth | stats count by user"

    _KEYWORDS = frozenset({"by", "as", "over", "output", "outputnew"})
    _SKIP_KEYWORDS_IN = frozenset({"search", "eval", "where", "fieldformat"})

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands():
            if not cmd.implicit and cmd.raw_name and cmd.raw_name != cmd.raw_name.lower() and cmd.name != "`macro`":
                start, end = cmd.name_span
                yield self.finding(f"Write the command as `{cmd.raw_name.lower()}`.", start, end)
            if cmd.name in self._SKIP_KEYWORDS_IN:
                continue
            for tok in cmd.tokens():
                if tok.kind == WORD and tok.value.lower() in self._KEYWORDS and tok.value != tok.value.lower():
                    yield self.finding(f"Write `{tok.value.lower()}` in lowercase.", tok.start, tok.end)
