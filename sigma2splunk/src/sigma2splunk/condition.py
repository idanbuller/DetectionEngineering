"""Parse a Sigma condition into an AST and expand its quantifiers.

Supported: and, or, not, parentheses, `1 of X`, `all of X`, `1 of them`,
`all of them`, and selection-name patterns with `*` (e.g. `1 of selection_*`).
`N of ...` with N > 1 is not supported (Splunk search has no native N-of).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import List, Union

from .errors import UnsupportedSigma

_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_KEYWORDS = {"and", "or", "not", "of", "them"}


@dataclass
class Ref:
    name: str


@dataclass
class Not:
    node: Node


@dataclass
class And:
    nodes: List[Node]


@dataclass
class Or:
    nodes: List[Node]


@dataclass
class Quant:
    quantifier: str  # "1" | "all" | a number
    pattern: str  # a selection name, a glob, or "them"


Node = Union[Ref, Not, And, Or, Quant]


class _Parser:
    def __init__(self, tokens: List[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self._or()
        if self.peek() is not None:
            raise UnsupportedSigma(f"unexpected token in condition: {self.peek()!r}")
        return node

    def _or(self) -> Node:
        nodes = [self._and()]
        while self.peek() == "or":
            self.next()
            nodes.append(self._and())
        return nodes[0] if len(nodes) == 1 else Or(nodes)

    def _and(self) -> Node:
        nodes = [self._factor()]
        while self.peek() == "and":
            self.next()
            nodes.append(self._factor())
        return nodes[0] if len(nodes) == 1 else And(nodes)

    def _factor(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise UnsupportedSigma("condition ended unexpectedly")
        if tok == "not":
            self.next()
            return Not(self._factor())
        if tok == "(":
            self.next()
            node = self._or()
            if self.next() != ")":
                raise UnsupportedSigma("unbalanced parentheses in condition")
            return node
        if tok in ("1", "all") or tok.isdigit():
            self.next()
            if self.next() != "of":
                raise UnsupportedSigma(f"expected 'of' after {tok!r} in condition")
            pattern = self.next()
            if pattern is None:
                raise UnsupportedSigma("expected a selection after 'of'")
            return Quant(tok, pattern)
        if tok in _KEYWORDS:
            raise UnsupportedSigma(f"unexpected keyword {tok!r} in condition")
        self.next()
        return Ref(tok)


def parse_condition(condition: str) -> Node:
    tokens = _TOKEN.findall(condition)
    if not tokens:
        raise UnsupportedSigma("empty condition")
    return _Parser(tokens).parse()


def expand(node: Node, selection_names: List[str]) -> Node:
    """Resolve Quant nodes against the rule's selection names."""
    if isinstance(node, Ref):
        if node.name not in selection_names:
            raise UnsupportedSigma(f"condition references unknown selection {node.name!r}")
        return node
    if isinstance(node, Not):
        return Not(expand(node.node, selection_names))
    if isinstance(node, And):
        return And([expand(n, selection_names) for n in node.nodes])
    if isinstance(node, Or):
        return Or([expand(n, selection_names) for n in node.nodes])
    if isinstance(node, Quant):
        return _expand_quant(node, selection_names)
    raise UnsupportedSigma(f"unhandled condition node {node!r}")


def _expand_quant(node: Quant, selection_names: List[str]) -> Node:
    if node.pattern == "them":
        matches = list(selection_names)
    else:
        matches = [n for n in selection_names if fnmatch.fnmatchcase(n, node.pattern)]
    if not matches:
        raise UnsupportedSigma(f"'{node.quantifier} of {node.pattern}' matched no selections")
    refs: List[Node] = [Ref(n) for n in matches]
    if node.quantifier == "all":
        return And(refs) if len(refs) > 1 else refs[0]
    if node.quantifier == "1":
        return Or(refs) if len(refs) > 1 else refs[0]
    raise UnsupportedSigma(f"'{node.quantifier} of ...' is not supported (only 1 of / all of)")
