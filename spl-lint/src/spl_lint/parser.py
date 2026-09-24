"""Just enough SPL structure for linting.

SPL has no published grammar, so this is not a full parser. It splits a query
into pipelines and commands, understands quoting, ``` comments ```, `macros`
and [subsearches], and gives each command a token stream. It never rejects a
query: anything it cannot make sense of becomes a diagnostic (rule SPL000) and
parsing carries on.

All offsets are character offsets into the original query text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

# Commands whose arguments are eval expressions rather than search terms.
EVAL_COMMANDS = frozenset({"eval", "where", "fieldformat"})

# Generating commands that may start a subsearch without a leading pipe,
# e.g. [inputlookup allowlist.csv | fields user].
SUBSEARCH_GENERATING_COMMANDS = frozenset(
    {
        "inputlookup",
        "inputcsv",
        "tstats",
        "mstats",
        "makeresults",
        "rest",
        "metadata",
        "datamodel",
        "from",
        "loadjob",
        "savedsearch",
        "eventcount",
        "dbinspect",
        "pivot",
    }
)

# Commands whose [ ... ] block is a pipeline fragment run on the current
# results, not a subsearch that starts with a base search.
CONTINUATION_COMMANDS = frozenset({"appendpipe", "foreach"})

# Token kinds
WORD = "WORD"
NUMBER = "NUMBER"
STRING = "STRING"  # "double quoted"; value excludes the quotes
SQSTRING = "SQSTRING"  # 'single quoted' (eval field reference)
OP = "OP"
LPAREN = "LPAREN"
RPAREN = "RPAREN"
COMMA = "COMMA"
MACRO = "MACRO"  # `macro(args)`; value excludes the backticks
SUBSEARCH = "SUBSEARCH"  # [ ... ]; value is empty
PLACEHOLDER = "PLACEHOLDER"  # %template_var% or $token$, substituted before the search runs

_SEARCH_OPS = ("!=", "<=", ">=", "==", "=", "<", ">")
_EVAL_OPS = ("!=", "<=", ">=", "==", "=", "<", ">", "+", "-", "*", "/", "%", ".")
_SEARCH_WORD = re.compile(r"(?:\\.|[^\s\"`()\[\],=!<>\\])+")
_EVAL_WORD = re.compile(r"[^\s\"'`()\[\],=!<>+\-*/%.]+")
_NUMBER = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_PLACEHOLDER = re.compile(r"%[\w.]+%|\$[\w.]+\$")
_COMMAND_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COMMENT = re.compile(r"```.*?```", re.DOTALL)
_DIRECTIVE = re.compile(r"spl-lint\s*:\s*disable(?:\s*=\s*([\w-]+(?:\s*,\s*[\w-]+)*))?", re.IGNORECASE)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class Diagnostic:
    message: str
    start: int
    end: int


@dataclass
class Command:
    """One pipe-delimited segment of a pipeline."""

    name: str  # lowercase command name; "search" for an implicit base search
    raw_name: str  # the name as written ("" when implicit)
    implicit: bool
    start: int  # first non-space character of the segment
    end: int  # end of the segment (exclusive), trailing space trimmed
    args_start: int
    position: int  # index within the pipeline
    pipeline: Pipeline
    subsearches: List[Pipeline] = field(default_factory=list)
    _query: ParsedQuery = field(default=None, repr=False)  # type: ignore[assignment]
    _tokens: Optional[List[Token]] = field(default=None, repr=False)

    @property
    def is_eval(self) -> bool:
        return self.name in EVAL_COMMANDS

    @property
    def name_span(self) -> Tuple[int, int]:
        if self.implicit:
            return self.start, min(self.end, self.start + 1)
        return self.start, self.args_start

    @property
    def text(self) -> str:
        return self._query.text[self.start : self.end]

    def tokens(self) -> List[Token]:
        """Argument tokens (the command name itself is excluded)."""
        if self._tokens is None:
            self._tokens = self._query._tokenize(
                self.args_start, self.end, eval_mode=self.is_eval, subsearches=self.subsearches
            )
        return self._tokens

    def next_command(self) -> Optional[Command]:
        cmds = self.pipeline.commands
        return cmds[self.position + 1] if self.position + 1 < len(cmds) else None


@dataclass
class Pipeline:
    start: int
    end: int
    commands: List[Command] = field(default_factory=list)
    is_subsearch: bool = False
    leading_pipe: bool = False
    owner: Optional[Command] = None  # command whose [ ... ] this is


class ParsedQuery:
    def __init__(self, text: str) -> None:
        self.text = text
        self.diagnostics: List[Diagnostic] = []
        self.comments: List[Tuple[int, int, str]] = []
        self.masked = self._mask_comments(text)
        self.suppressed = self._read_directives()
        self._close_cache: Dict[int, Optional[int]] = {}
        self.root = self._parse_pipeline(0, len(text), is_subsearch=False, continuation=False)
        for cmd in self.commands():
            cmd.tokens()  # tokenize eagerly so paren diagnostics are collected
        # The same span can be scanned more than once (e.g. inside a subsearch).
        self.diagnostics = sorted(set(self.diagnostics), key=lambda d: (d.start, d.message))

    # -- traversal ---------------------------------------------------------

    def pipelines(self) -> Iterator[Pipeline]:
        stack = [self.root]
        while stack:
            pipeline = stack.pop(0)
            yield pipeline
            for cmd in pipeline.commands:
                stack.extend(cmd.subsearches)

    def commands(self, *names: str) -> Iterator[Command]:
        for pipeline in self.pipelines():
            for cmd in pipeline.commands:
                if not names or cmd.name in names:
                    yield cmd

    # -- comments and directives ------------------------------------------

    def _mask_comments(self, text: str) -> str:
        """Blank out ``` comments ``` so later passes never see their content."""
        out = []
        pos = 0
        for m in _COMMENT.finditer(text):
            self.comments.append((m.start(), m.end(), m.group()[3:-3]))
            out.append(text[pos : m.start()])
            out.append(re.sub(r"[^\n]", " ", m.group()))
            pos = m.end()
        rest = text[pos:]
        unclosed = rest.find("```")
        if unclosed != -1:
            start = pos + unclosed
            self.diagnostics.append(Diagnostic("Unterminated ``` comment", start, start + 3))
            self.comments.append((start, len(text), rest[unclosed + 3 :]))
            rest = rest[:unclosed] + re.sub(r"[^\n]", " ", rest[unclosed:])
        out.append(rest)
        return "".join(out)

    def _read_directives(self) -> Optional[set]:
        """Rule IDs disabled by ``` spl-lint: disable=SPL101,SPL204 ``` comments.

        Returns None when nothing is disabled and {"all"} for a bare disable.
        """
        disabled: set = set()
        for _, _, content in self.comments:
            for m in _DIRECTIVE.finditer(content):
                if not m.group(1):
                    disabled.add("all")
                else:
                    disabled.update(p.strip().upper() for p in m.group(1).split(",") if p.strip())
        return disabled or None

    # -- scanning helpers ---------------------------------------------------

    def _skip_string(self, i: int, end: int, quote: str = '"') -> int:
        """Return the offset just past the string starting at i."""
        s = self.masked
        j = i + 1
        while j < end:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == quote:
                return j + 1
            j += 1
        self.diagnostics.append(Diagnostic("Unterminated string", i, i + 1))
        return end

    def _skip_macro(self, i: int, end: int) -> int:
        j = self.masked.find("`", i + 1, end)
        if j == -1:
            self.diagnostics.append(Diagnostic("Unterminated `macro`", i, i + 1))
            return end
        return j + 1

    def _find_close_bracket(self, i: int, end: int) -> Optional[int]:
        """Offset of the ']' matching the '[' at i, or None."""
        if i in self._close_cache:
            return self._close_cache[i]
        s = self.masked
        depth = 0
        j = i
        result = None
        while j < end:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                j = self._skip_string(j, end)
                continue
            if c == "`":
                j = self._skip_macro(j, end)
                continue
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    result = j
                    break
            j += 1
        self._close_cache[i] = result
        return result

    # -- pipelines ------------------------------------------------------------

    def _parse_pipeline(self, start: int, end: int, is_subsearch: bool, continuation: bool) -> Pipeline:
        s = self.masked
        pipeline = Pipeline(start=start, end=end, is_subsearch=is_subsearch)
        segments: List[Tuple[int, int, List[Tuple[int, int]]]] = []
        seg_start = start
        subs: List[Tuple[int, int]] = []
        i = start
        while i < end:
            c = s[i]
            if c == "\\":
                i += 2  # an escaped character outside a string, e.g. \" in a search term
                continue
            if c == '"':
                i = self._skip_string(i, end)
                continue
            if c == "`":
                i = self._skip_macro(i, end)
                continue
            if c == "[":
                close = self._find_close_bracket(i, end)
                if close is None:
                    self.diagnostics.append(Diagnostic("Unclosed [ subsearch", i, i + 1))
                    i += 1
                    continue
                subs.append((i, close))
                i = close + 1
                continue
            if c == "]":
                self.diagnostics.append(Diagnostic("Unmatched ]", i, i + 1))
            elif c == "|":
                segments.append((seg_start, i, subs))
                seg_start, subs = i + 1, []
            i += 1
        segments.append((seg_start, end, subs))

        for n, (a, b, seg_subs) in enumerate(segments):
            lo, hi = _trim(s, a, b)
            if lo == hi:
                if n == 0 and len(segments) > 1:
                    pipeline.leading_pipe = True
                    continue
                if n == 0 and len(segments) == 1:
                    continue  # empty query or empty subsearch
                pos = a - 1 if a > 0 else a
                self.diagnostics.append(Diagnostic("Empty command between pipes", pos, pos + 1))
                continue
            first = not pipeline.commands
            cmd = self._make_command(pipeline, lo, hi, first and not pipeline.leading_pipe and not continuation)
            pipeline.commands.append(cmd)
            for sa, sb in seg_subs:
                inner = self._parse_pipeline(
                    sa + 1, sb, is_subsearch=True, continuation=cmd.name in CONTINUATION_COMMANDS
                )
                inner.owner = cmd
                cmd.subsearches.append(inner)
        return pipeline

    def _make_command(self, pipeline: Pipeline, lo: int, hi: int, may_be_implicit: bool) -> Command:
        s = self.masked
        position = len(pipeline.commands)
        if s[lo] == "`" and not may_be_implicit:
            close = self.masked.find("`", lo + 1, hi)
            name_end = close + 1 if close != -1 else hi
            raw = s[lo:name_end]
            return Command("`macro`", raw, False, lo, hi, name_end, position, pipeline, _query=self)
        m = _COMMAND_NAME.match(s, lo, hi)
        word = m.group() if m else ""
        followed_by_space = m is not None and (m.end() == hi or s[m.end()].isspace() or s[m.end()] in "[(")
        explicit = word.lower() == "search" or (pipeline.is_subsearch and word.lower() in SUBSEARCH_GENERATING_COMMANDS)
        if may_be_implicit and not (explicit and followed_by_space):
            return Command("search", "", True, lo, hi, lo, position, pipeline, _query=self)
        if not m:
            self.diagnostics.append(Diagnostic("Expected a command name after |", lo, lo + 1))
            return Command("", "", False, lo, hi, lo, position, pipeline, _query=self)
        return Command(word.lower(), word, False, lo, hi, m.end(), position, pipeline, _query=self)

    # -- tokens ---------------------------------------------------------------

    def _tokenize(self, start: int, end: int, eval_mode: bool, subsearches: List[Pipeline]) -> List[Token]:
        s = self.masked
        sub_at = {p.start - 1: p.end + 1 for p in subsearches}  # '[' offset -> past ']'
        ops = _EVAL_OPS if eval_mode else _SEARCH_OPS
        word_re = _EVAL_WORD if eval_mode else _SEARCH_WORD
        tokens: List[Token] = []
        depth = 0
        i = start
        while i < end:
            c = s[i]
            if c.isspace():
                i += 1
                continue
            if c == '"':
                j = self._skip_string(i, end)
                tokens.append(Token(STRING, self.text[i + 1 : max(i + 1, j - 1)], i, j))
                i = j
                continue
            if c == "'" and eval_mode:
                j = self._skip_string(i, end, quote="'")
                tokens.append(Token(SQSTRING, self.text[i + 1 : max(i + 1, j - 1)], i, j))
                i = j
                continue
            if c == "`":
                j = self._skip_macro(i, end)
                tokens.append(Token(MACRO, self.text[i + 1 : max(i + 1, j - 1)], i, j))
                i = j
                continue
            if c == "[" and i in sub_at:
                tokens.append(Token(SUBSEARCH, "", i, sub_at[i]))
                i = sub_at[i]
                continue
            if c == "(":
                depth += 1
                tokens.append(Token(LPAREN, c, i, i + 1))
                i += 1
                continue
            if c == ")":
                depth -= 1
                if depth < 0:
                    self.diagnostics.append(Diagnostic("Unmatched )", i, i + 1))
                    depth = 0
                tokens.append(Token(RPAREN, c, i, i + 1))
                i += 1
                continue
            if c == ",":
                tokens.append(Token(COMMA, c, i, i + 1))
                i += 1
                continue
            if eval_mode and c.isdigit():
                m = _NUMBER.match(s, i, end)
                tokens.append(Token(NUMBER, m.group(), i, m.end()))
                i = m.end()
                continue
            op = next((o for o in ops if s.startswith(o, i)), None)
            if op:
                tokens.append(Token(OP, op, i, i + len(op)))
                i += len(op)
                continue
            m = word_re.match(s, i, end)
            if m:
                value = m.group()
                if _PLACEHOLDER.fullmatch(value):
                    kind = PLACEHOLDER
                elif not eval_mode and _NUMBER.fullmatch(value):
                    kind = NUMBER
                else:
                    kind = WORD
                tokens.append(Token(kind, value, i, m.end()))
                i = m.end()
                continue
            tokens.append(Token(OP, c, i, i + 1))
            i += 1
        if depth > 0:
            opener = max(t.start for t in tokens if t.kind == LPAREN)
            self.diagnostics.append(Diagnostic("Unclosed (", opener, opener + 1))
        return tokens


def _trim(s: str, a: int, b: int) -> Tuple[int, int]:
    while a < b and s[a].isspace():
        a += 1
    while b > a and s[b - 1].isspace():
        b -= 1
    return a, b


def parse(text: str) -> ParsedQuery:
    return ParsedQuery(text)
