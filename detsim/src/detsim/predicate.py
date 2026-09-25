"""Turn a detection's SPL into a boolean AST of its match conditions, and match events against it.

Uses spl-lint's tokenizer, then parses the search commands' arguments into And/Or/Not/Cmp nodes.
`| spath` stages are ignored: they only create the aliases the search then matches on, and
detsim synthesizes those aliases directly.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Dict, List, Union

from spl_lint.parser import LPAREN, NUMBER, RPAREN, STRING, WORD, parse

COMPARE = {"=", "==", "!=", "<", "<=", ">", ">="}


@dataclass
class Cmp:
    field: str
    op: str
    value: str
    wildcard: bool  # the value came from a quoted string (Splunk wildcards active)
    numeric: bool = False


@dataclass
class Term:  # a bare full-text keyword
    text: str


@dataclass
class Not:
    node: Node


@dataclass
class And:
    nodes: List[Node] = field(default_factory=list)


@dataclass
class Or:
    nodes: List[Node] = field(default_factory=list)


Node = Union[Cmp, Term, Not, And, Or]


class PredicateError(ValueError):
    pass


class _TokenParser:
    def __init__(self, tokens) -> None:
        self.t = tokens
        self.i = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def _is(self, kind, value=None):
        tok = self.peek()
        return tok is not None and tok.kind == kind and (value is None or tok.value == value)

    def parse(self) -> Node:
        node = self._or()
        return node

    def _or(self) -> Node:
        nodes = [self._and()]
        while self._is(WORD, "OR"):
            self.i += 1
            nodes.append(self._and())
        return nodes[0] if len(nodes) == 1 else Or(nodes)

    def _and(self) -> Node:
        nodes = [self._term()]
        while True:
            if self._is(WORD, "AND"):
                self.i += 1
                nodes.append(self._term())
                continue
            tok = self.peek()
            if tok is None or tok.kind == RPAREN or self._is(WORD, "OR"):
                break
            nodes.append(self._term())  # implicit AND
        return nodes[0] if len(nodes) == 1 else And(nodes)

    def _term(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise PredicateError("unexpected end of predicate")
        if tok.kind == WORD and tok.value == "NOT":
            self.i += 1
            return Not(self._term())
        if tok.kind == LPAREN:
            self.i += 1
            node = self._or()
            if not self._is(RPAREN):
                raise PredicateError("unbalanced parentheses")
            self.i += 1
            return node
        # comparison: FIELD OP VALUE, or FIELD IN (...)
        nxt = self.t[self.i + 1] if self.i + 1 < len(self.t) else None
        if tok.kind == WORD and nxt is not None and nxt.kind == "OP" and nxt.value in COMPARE:
            value = self.t[self.i + 2] if self.i + 2 < len(self.t) else None
            if value is None:
                raise PredicateError(f"missing value after {tok.value}{nxt.value}")
            self.i += 3
            return Cmp(tok.value, nxt.value, value.value, value.kind == STRING, value.kind == NUMBER)
        if tok.kind == WORD and nxt is not None and nxt.kind == WORD and nxt.value == "IN":
            return self._in_clause(tok.value)
        # a bare keyword / full-text term
        self.i += 1
        return Term(tok.value)

    def _in_clause(self, field_name: str) -> Node:
        self.i += 2  # field IN
        if not self._is(LPAREN):
            raise PredicateError("expected ( after IN")
        self.i += 1
        options = []
        while not self._is(RPAREN):
            tok = self.peek()
            if tok is None:
                raise PredicateError("unterminated IN (")
            if tok.kind in (WORD, STRING, NUMBER):
                options.append(Cmp(field_name, "=", tok.value, tok.kind == STRING, tok.kind == NUMBER))
            self.i += 1
        self.i += 1
        return Or(options) if len(options) > 1 else options[0]


@dataclass
class Predicate:
    ast: Node
    search_args: List[str]  # the raw argument text of each search command, for a verification search


def from_spl(spl: str) -> Predicate:
    query = parse(spl)
    if query.diagnostics:
        d = query.diagnostics[0]
        raise PredicateError(f"the detection doesn't parse: {d.message}")
    parts: List[Node] = []
    args: List[str] = []
    for cmd in query.commands():
        if cmd.name != "search":
            continue
        tokens = cmd.tokens()
        if not tokens:
            continue
        node = _TokenParser(tokens).parse()
        parts.append(node)
        args.append(query.text[cmd.args_start : cmd.end].strip())
    if not parts:
        raise PredicateError("no search terms found in the detection")
    ast = parts[0] if len(parts) == 1 else And(parts)
    return Predicate(ast, args)


# -- matching an event against the AST (Splunk-ish semantics) -------------------


def _values(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    return [] if v is None else [str(v)]


def matches(node: Node, event: Dict[str, Any]) -> bool:
    if isinstance(node, And):
        return all(matches(n, event) for n in node.nodes)
    if isinstance(node, Or):
        return any(matches(n, event) for n in node.nodes)
    if isinstance(node, Not):
        return not matches(node.node, event)
    if isinstance(node, Term):
        hay = " ".join(f"{k}={v}" for k, v in event.items()) + " " + str(event.get("_raw", ""))
        return node.text.strip('"').lower() in hay.lower()
    if isinstance(node, Cmp):
        return _match_cmp(node, event)
    raise PredicateError(f"unhandled node {type(node).__name__}")


def _match_cmp(c: Cmp, event: Dict[str, Any]) -> bool:
    present = c.field in event and event[c.field] is not None
    vals = _values(event.get(c.field))
    if c.numeric or c.op in ("<", "<=", ">", ">="):
        try:
            left = float(vals[0]) if vals else None
            right = float(c.value)
        except (ValueError, IndexError):
            return False
        if left is None:
            return False
        return {
            "<": left < right,
            "<=": left <= right,
            ">": left > right,
            ">=": left >= right,
            "=": left == right,
            "==": left == right,
            "!=": left != right,
        }[c.op]
    if c.op in ("!=",):
        return not _match_eq(c, vals, present)
    return _match_eq(c, vals, present)


def _match_eq(c: Cmp, vals: List[str], present: bool) -> bool:
    if c.value == "*":
        return present
    pattern = c.value
    for v in vals:
        if "*" in pattern:
            if fnmatch.fnmatchcase(v.lower(), pattern.lower()):
                return True
        elif v.lower() == pattern.lower():
            return True
    return False
