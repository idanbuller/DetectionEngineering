"""Rules for queries that run but silently return the wrong results."""

from __future__ import annotations

import re
from typing import Iterator

from ..parser import LPAREN, NUMBER, SQSTRING, STRING, WORD, ParsedQuery
from ._helpers import (
    IDENTIFIER,
    call_args,
    eval_assignments,
    eval_commands,
    is_op,
    next_tok,
    prev_tok,
    search_commands,
)
from .base import Finding, Rule, Severity, register


@register
class SyntaxError_(Rule):
    id = "SPL000"
    name = "syntax-error"
    category = "syntax"
    severity = Severity.ERROR
    summary = "The query has unbalanced quotes, brackets, parentheses or an empty pipe."
    explanation = """
        spl-lint found a structural problem such as an unterminated string, an
        unclosed subsearch bracket or parenthesis, or two pipes with nothing
        between them. Splunk will reject the search, or worse, parse it
        differently from how it reads.
    """
    bad = 'index=web status="500 | stats count by host'
    good = 'index=web status="500" | stats count by host'

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for d in query.diagnostics:
            yield self.finding(d.message, d.start, d.end)


@register
class LowercaseBoolean(Rule):
    id = "SPL101"
    name = "lowercase-boolean-operator"
    category = "correctness"
    severity = Severity.WARNING
    summary = "Lowercase and/or/not/in in a search are literal terms, not operators."
    explanation = """
        In the search command (including the implicit base search) the boolean
        operators AND, OR and NOT and the IN operator are only recognised in
        uppercase. A lowercase `or` is searched for as the literal word "or",
        so `user=alice or user=bob` requires both user values *and* the word
        "or" in the raw event, which almost never matches.

        eval and where accept either case; this rule only looks at search.
    """
    bad = "index=auth action=failure user=admin or user=root"
    good = "index=auth action=failure (user=admin OR user=root)"

    _WORDS = {"and", "or", "not"}

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in search_commands(query):
            tokens = cmd.tokens()
            for i, tok in enumerate(tokens):
                if tok.kind != WORD or tok.value == tok.value.upper():
                    continue
                lower = tok.value.lower()
                before, after = prev_tok(tokens, i), next_tok(tokens, i)
                if is_op(before) or is_op(after):
                    continue  # a field name or a value, e.g. mode=and
                if lower in self._WORDS or (
                    lower == "in"
                    and after is not None
                    and after.kind == LPAREN
                    and before is not None
                    and before.kind == WORD
                ):
                    yield self.finding(
                        f'"{tok.value}" is searched as a literal word, not an operator; write {tok.value.upper()}.',
                        tok.start,
                        tok.end,
                    )


@register
class WildcardInEvalComparison(Rule):
    id = "SPL102"
    name = "wildcard-in-eval-comparison"
    category = "correctness"
    severity = Severity.ERROR
    summary = "`*` is a literal character in eval/where comparisons."
    explanation = """
        `where user="*admin*"` compares against the literal string `*admin*`
        (asterisks included). Wildcards only work in the search command. In
        eval and where, use like() with `%` or match() with a regex, or move
        the filter into the base search.

        Only strings that look like wildcard patterns (a `*` at the start or
        end next to other text) are flagged, so an intentional comparison with
        a literal `*`, such as an IAM policy action of "*", is left alone.
    """
    bad = 'index=auth | where user="svc_*"'
    good = 'index=auth | where like(user, "svc_%")'

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in eval_commands(query):
            tokens = cmd.tokens()
            targets = eval_assignments(cmd)
            for i, tok in enumerate(tokens):
                if not is_op(tok, "=", "==", "!="):
                    continue
                if tok.value == "=" and (i - 1) in targets:
                    continue  # eval assignment, not a comparison
                value = next_tok(tokens, i)
                if value is not None and value.kind == STRING and _looks_like_glob(value.value):
                    yield self.finding(
                        f'"{value.value}" is compared literally; `*` is not a wildcard in '
                        f"{cmd.name}. Use like() with % or match() instead.",
                        value.start,
                        value.end,
                    )


@register
class LikeWithAsterisk(Rule):
    id = "SPL103"
    name = "like-with-asterisk"
    category = "correctness"
    severity = Severity.ERROR
    summary = "like() uses % and _ as wildcards, not *."
    explanation = """
        The like() function (and the LIKE operator in where) uses SQL-style
        wildcards: `%` for any run of characters and `_` for one character.
        An asterisk is matched literally, so `like(process, "*powershell*")`
        only matches a process name that contains the asterisks.
    """
    bad = 'index=edr | where like(process_name, "*powershell*")'
    good = 'index=edr | where like(process_name, "%powershell%")'

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in eval_commands(query):
            tokens = cmd.tokens()
            for i, tok in enumerate(tokens):
                if tok.kind != WORD or tok.value.lower() != "like":
                    continue
                after = next_tok(tokens, i)
                pattern = None
                if after is not None and after.kind == LPAREN:
                    args, _ = call_args(tokens, i + 1)
                    if len(args) >= 2 and len(args[1]) == 1:
                        pattern = args[1][0]
                elif after is not None and tok.value == "LIKE":
                    pattern = after
                if pattern is not None and pattern.kind == STRING and "*" in pattern.value and "%" not in pattern.value:
                    yield self.finding(
                        f'like() pattern "{pattern.value}" uses `*`; like() wildcards are `%` and `_`.',
                        pattern.start,
                        pattern.end,
                    )


def _looks_like_glob(value: str) -> bool:
    """True for "svc_*" or "*admin*"; false for a bare "*" or "(*)"."""
    return (value.startswith("*") or value.endswith("*")) and any(ch.isalnum() for ch in value)


@register
class UnquotedDottedField(Rule):
    id = "SPL104"
    name = "unquoted-dotted-field"
    category = "correctness"
    severity = Severity.ERROR
    summary = "In eval/where, `a.b` means field a concatenated with field b."
    explanation = """
        `.` is the string concatenation operator in eval expressions. An
        unquoted `process.name` is evaluated as the field `process` joined to
        the field `name`; both usually don't exist, so the result is null and
        the comparison is silently false. This is the classic cause of
        detections on JSON sources (nested fields) or tstats data model fields
        (`Processes.process_name`) returning nothing.

        Wrap the field name in single quotes (`'process.name'`), or rename or
        spath it to a name without dots first. If you really mean
        concatenation, put spaces around the operator (`a . b`) so the intent
        is obvious to the next reader and to this rule.
    """
    bad = 'index=edr | where process.name="powershell.exe"'
    good = "index=edr | where 'process.name'=\"powershell.exe\""

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in eval_commands(query):
            tokens = cmd.tokens()
            targets = eval_assignments(cmd)
            i = 0
            while i < len(tokens):
                end = _dotted_chain_end(tokens, i)
                if end is None:
                    i += 1
                    continue
                if i not in targets:
                    name = query.text[tokens[i].start : tokens[end].end]
                    parts = name.split(".")
                    yield self.finding(
                        f"`{name}` is evaluated as {' . '.join(parts)} (concatenation). Quote it as "
                        f"'{name}' if it is one field, or write {' . '.join(parts)} if you meant concatenation.",
                        tokens[i].start,
                        tokens[end].end,
                    )
                i = end + 1


def _dotted_chain_end(tokens, i):
    """If tokens[i] starts an adjacent `ident.ident[.ident...]` chain, its last index."""
    if tokens[i].kind != WORD or not IDENTIFIER.fullmatch(tokens[i].value):
        return None
    j = i
    while (
        j + 2 < len(tokens)
        and is_op(tokens[j + 1], ".")
        and tokens[j + 1].start == tokens[j].end
        and tokens[j + 2].start == tokens[j + 1].end
        and tokens[j + 2].kind in (WORD, NUMBER)
        and (tokens[j + 2].kind == NUMBER or IDENTIFIER.fullmatch(tokens[j + 2].value))
    ):
        j += 2
    if j == i:
        return None
    after = next_tok(tokens, j)
    if after is not None and after.kind == LPAREN and after.start == tokens[j].end:
        return None  # a dotted function name; not something eval has, but not our business
    return j


@register
class SingleQuotedLiteral(Rule):
    id = "SPL105"
    name = "single-quoted-literal"
    category = "correctness"
    severity = Severity.WARNING
    summary = "Single quotes in eval/where reference a field, not a string."
    explanation = """
        In eval and where, 'single quotes' name a field and "double quotes"
        make a string. `where path='C:\\Windows\\Temp'` compares the path field
        with a field called `C:\\Windows\\Temp`, which doesn't exist. This rule
        flags single-quoted values that contain characters (\\ / * %) that
        almost never appear in field names.
    """
    bad = "index=edr | where file_path='C:\\\\Windows\\\\Temp'"
    good = 'index=edr | where file_path="C:\\\\Windows\\\\Temp"'

    _SUSPICIOUS = re.compile(r"[\\/*%]")

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in eval_commands(query):
            for tok in cmd.tokens():
                if tok.kind == SQSTRING and self._SUSPICIOUS.search(tok.value):
                    yield self.finding(
                        f"'{tok.value}' is a field reference in {cmd.name}; "
                        f'use double quotes for a string: "{tok.value}".',
                        tok.start,
                        tok.end,
                    )


@register
class SortDefaultLimit(Rule):
    id = "SPL106"
    name = "sort-default-limit"
    category = "correctness"
    severity = Severity.WARNING
    summary = "sort keeps only 10,000 results unless you give it a count."
    explanation = """
        `sort` without a count returns at most 10,000 results and drops the
        rest without a warning. Anything after it (dedup, streamstats, the
        alert itself) only sees the first 10,000. Use `sort 0 <fields>` to keep
        everything, or give an explicit count. A sort followed directly by
        `head` is not flagged.
    """
    bad = "index=proxy | stats count by user | sort -count | streamstats count as rank"
    good = "index=proxy | stats count by user | sort 0 -count | streamstats count as rank"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands("sort"):
            tokens = cmd.tokens()
            if tokens and tokens[0].kind == NUMBER:
                continue
            if any(
                t.kind == WORD and t.value.lower() == "limit" and is_op(next_tok(tokens, i), "=")
                for i, t in enumerate(tokens)
            ):
                continue
            nxt = cmd.next_command()
            if nxt is not None and nxt.name in ("head", "tail"):
                continue
            start, end = cmd.name_span
            yield self.finding(
                "sort without a count truncates to 10,000 results; use `sort 0 ...` to keep all.",
                start,
                end,
            )


@register
class NotEqualExcludesNull(Rule):
    id = "SPL107"
    name = "not-equal-excludes-null"
    category = "correctness"
    severity = Severity.INFO
    summary = "field!=value in a search also drops events that lack the field."
    explanation = """
        In search, `field!=value` only matches events where the field exists
        and has a different value. `NOT field=value` also matches events where
        the field is missing. In an exclusion, `!=` can hide exactly the odd
        events you want to see (a new log format, a parsing failure). Pick the
        one you mean.
    """
    bad = "index=auth action!=success"
    good = "index=auth NOT action=success"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in search_commands(query):
            tokens = cmd.tokens()
            for i, tok in enumerate(tokens):
                if is_op(tok, "!="):
                    field = prev_tok(tokens, i)
                    if field is not None and field.kind == WORD and field.value.lower() == "index":
                        continue
                    name = field.value if field is not None else "field"
                    yield self.finding(
                        f"{name}!=... also drops events without {name}; use NOT {name}=... to keep them.",
                        tok.start,
                        tok.end,
                    )
