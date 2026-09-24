"""Rules for queries that are slow, expensive, or silently truncated at scale."""

from __future__ import annotations

from typing import Iterator

from ..parser import MACRO, PLACEHOLDER, STRING, WORD, ParsedQuery
from ._helpers import base_searches, is_op, next_tok, prev_tok, search_commands
from .base import Finding, Rule, Severity, register


def _is_index_term(tokens, i) -> bool:
    tok = tokens[i]
    if tok.kind != WORD:
        return False
    lower = tok.value.lower()
    if lower.startswith("index::"):
        return True
    if lower != "index":
        return False
    after = next_tok(tokens, i)
    return is_op(after, "=", "!=") or (after is not None and after.kind == WORD and after.value.upper() == "IN")


@register
class MissingIndex(Rule):
    id = "SPL201"
    name = "missing-index"
    category = "performance"
    severity = Severity.WARNING
    summary = "Base search does not name an index."
    explanation = """
        A base search without `index=` searches the user's default indexes.
        That makes the result depend on who (or which service account) runs
        it, and usually scans far more data than needed. Name the index, or
        use a macro that does. A base search that uses a macro or a template
        placeholder (`%search%`, `$token$`) is assumed to get its index from
        there and is not flagged.
    """
    bad = "sourcetype=linux_secure action=failure | stats count by src"
    good = "index=os sourcetype=linux_secure action=failure | stats count by src"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in base_searches(query):
            tokens = cmd.tokens()
            if not tokens:
                continue
            if any(t.kind in (MACRO, PLACEHOLDER) for t in tokens):
                continue  # the index is expected to come from the macro or template
            if any(_is_index_term(tokens, i) for i in range(len(tokens))):
                continue
            yield self.finding(
                "Base search has no index; name one (index=...) so it doesn't depend on the runner's default indexes.",
                tokens[0].start,
                tokens[0].end,
            )


@register
class IndexWildcard(Rule):
    id = "SPL202"
    name = "index-wildcard"
    category = "performance"
    severity = Severity.WARNING
    summary = "index=* searches every index the runner can read."
    explanation = """
        `index=*` scans every index the running user can access, which is slow
        and makes the result depend on that user's permissions. List the
        indexes you need, e.g. `index IN (os, edr)`.
    """
    bad = "index=* sourcetype=linux_secure"
    good = "index=os sourcetype=linux_secure"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in list(search_commands(query)) + list(query.commands("tstats")):
            tokens = cmd.tokens()
            for i, tok in enumerate(tokens):
                if tok.kind == WORD and tok.value.lower() == "index" and is_op(next_tok(tokens, i), "="):
                    value = tokens[i + 2] if i + 2 < len(tokens) else None
                    if value is not None and value.kind in (WORD, STRING) and value.value == "*":
                        yield self.finding("index=* scans every index; list the ones you need.", tok.start, value.end)


@register
class LeadingWildcard(Rule):
    id = "SPL203"
    name = "leading-wildcard"
    category = "performance"
    severity = Severity.INFO
    summary = "A leading wildcard in the base search forces a scan of every event."
    explanation = """
        Splunk finds events by looking up the terms of the base search in the
        index. A term that starts with `*` (`*admin`, `user=*svc*`) can't be
        looked up, so every event in the time range and index is read and
        checked. Anchor the start of the term where you can, and make sure the
        rest of the base search (index, sourcetype, event code) narrows the
        events first. Substring matches on command lines often need a leading
        wildcard, which is why this is reported as info. `field=*` on its own
        (field exists) is fine.
    """
    bad = "index=edr process_name=*powershell.exe"
    good = "index=edr process_name=powershell.exe"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in base_searches(query):
            tokens = cmd.tokens()
            for i, tok in enumerate(tokens):
                if tok.kind not in (WORD, STRING) or len(tok.value) < 2 or not tok.value.startswith("*"):
                    continue
                if is_op(next_tok(tokens, i)):
                    continue  # a field name, not a value
                field = tokens[i - 2] if is_op(prev_tok(tokens, i)) and i >= 2 else None
                if field is not None and field.kind == WORD and field.value.lower() == "index":
                    continue  # covered by index-wildcard
                yield self.finding(
                    f"Leading wildcard in `{tok.value}` can't use the index and scans every event.",
                    tok.start,
                    tok.end,
                )


@register
class Join(Rule):
    id = "SPL204"
    name = "join"
    category = "performance"
    severity = Severity.WARNING
    summary = "join silently truncates its subsearch; prefer stats."
    explanation = """
        join runs its right-hand side as a subsearch limited to 50,000 rows
        and 60 seconds by default. Rows past the limit are dropped without
        an error, so the join quietly misses matches on busy days, which is
        exactly when a detection matters. Search both datasets together and
        use `stats ... by <key>`, or use a lookup for reference data.
    """
    bad = "index=auth action=success | join user [search index=hr status=terminated]"
    good = (
        "(index=auth action=success) OR (index=hr status=terminated)\n"
        "| stats values(action) as action values(status) as status by user\n"
        '| where isnotnull(action) AND status="terminated"'
    )

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands("join"):
            start, end = cmd.name_span
            yield self.finding(
                "join drops subsearch rows past 50,000 / 60 s without an error; use stats by the key.",
                start,
                end,
            )


@register
class Transaction(Rule):
    id = "SPL205"
    name = "transaction"
    category = "performance"
    severity = Severity.WARNING
    summary = "transaction is memory-heavy and can silently split sessions."
    explanation = """
        transaction runs on the search head, holds open transactions in
        memory, and evicts them when its limits (maxopentxn, maxopenevents)
        are reached, splitting sessions without an error. For most detections,
        `stats min(_time) max(_time) values(...) by <session key>` or
        streamstats gives the same answer much faster and without eviction.
    """
    bad = "index=vpn | transaction user maxspan=1h | where eventcount > 10"
    good = "index=vpn | bin _time span=1h | stats count as eventcount by user _time | where eventcount > 10"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands("transaction"):
            start, end = cmd.name_span
            yield self.finding(
                "transaction can evict open sessions under load; prefer stats/streamstats by the session key.",
                start,
                end,
            )


@register
class SubsearchTruncation(Rule):
    id = "SPL206"
    name = "subsearch-truncation"
    category = "performance"
    severity = Severity.INFO
    summary = "Subsearch results are silently truncated."
    explanation = """
        Subsearches stop at 10,000 results (50,000 for append) and 60 seconds
        by default, and anything past the limit is dropped without failing the
        search. That is fine for a short allowlist lookup and dangerous for
        anything that grows with event volume. Prefer lookups or a single
        search with stats. join is reported separately by SPL204.
    """
    bad = "index=proxy [search index=threat_intel | fields dest]"
    good = "index=proxy | lookup threat_intel_domains dest output threat | where isnotnull(threat)"

    _SKIP = frozenset({"join", "appendpipe", "foreach"})

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands():
            if cmd.name in self._SKIP:
                continue
            for sub in cmd.subsearches:
                limit = "50,000" if cmd.name in ("append", "appendcols") else "10,000"
                yield self.finding(
                    f"Subsearch output is silently cut at {limit} results / 60 s.",
                    sub.start - 1,
                    sub.start,
                )


@register
class LateSearchFilter(Rule):
    id = "SPL207"
    name = "late-search-filter"
    category = "performance"
    severity = Severity.INFO
    summary = "| search right after the base search belongs in the base search."
    explanation = """
        A `| search` placed directly after the base search filters events only
        after they've been retrieved. Moving the terms into the base search
        lets Splunk use them to skip events when it reads the index.
    """
    bad = "index=auth sourcetype=linux_secure | search action=failure"
    good = "index=auth sourcetype=linux_secure action=failure"

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for first in base_searches(query):
            if all(t.kind in (MACRO, PLACEHOLDER) for t in first.tokens()):
                continue  # the macro or template may expand to a whole pipeline
            second = first.next_command()
            if second is not None and second.name == "search" and not second.implicit:
                start, end = second.name_span
                yield self.finding("Move these search terms into the base search.", start, end)


@register
class BareSpath(Rule):
    id = "SPL208"
    name = "bare-spath"
    category = "performance"
    severity = Severity.INFO
    summary = "spath without a path extracts every JSON field."
    explanation = """
        spath without a path extracts every field in the document, which is
        slow on large events and turns arrays into multivalue fields that
        break later comparisons. Extract what you need:
        `spath input=_raw path=process.name output=process_name`.
    """
    bad = 'index=edr sourcetype=edr:json | spath | where process_name="cmd.exe"'
    good = (
        "index=edr sourcetype=edr:json | spath input=_raw path=process.name output=process_name\n"
        '| where process_name="cmd.exe"'
    )

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands("spath"):
            tokens = cmd.tokens()
            keys = {t.value.lower() for i, t in enumerate(tokens) if t.kind == WORD and is_op(next_tok(tokens, i), "=")}
            positional = any(
                t.kind in (WORD, STRING) and not is_op(next_tok(tokens, i)) and not is_op(prev_tok(tokens, i))
                for i, t in enumerate(tokens)
            )
            if "path" not in keys and not positional:
                start, end = cmd.name_span
                yield self.finding("spath without path= extracts every field; name the path you need.", start, end)


@register
class TableBeforeProcessing(Rule):
    id = "SPL209"
    name = "table-before-processing"
    category = "performance"
    severity = Severity.INFO
    summary = "table in the middle of a pipeline moves all work to the search head."
    explanation = """
        table is a formatting command: everything after it runs on the search
        head instead of in parallel on the indexers. Use `fields` to trim
        fields mid-pipeline and keep `table` for the end.
    """
    bad = "index=web | table _time src uri status | stats count by src"
    good = "index=web | fields _time src uri status | stats count by src"

    _PRESENTATION = frozenset(
        {"table", "fields", "rename", "sort", "head", "tail", "reverse", "fieldformat", "outputlookup", "collect"}
    )

    def check(self, query: ParsedQuery) -> Iterator[Finding]:
        for cmd in query.commands("table"):
            later = cmd.pipeline.commands[cmd.position + 1 :]
            if any(c.name not in self._PRESENTATION for c in later):
                start, end = cmd.name_span
                yield self.finding("Use fields instead of table before further processing.", start, end)
