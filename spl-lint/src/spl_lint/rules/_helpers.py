from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set, Tuple

from ..parser import COMMA, LPAREN, OP, RPAREN, Command, ParsedQuery, Token

COMPARISON_OPS = frozenset({"=", "==", "!=", "<", ">", "<=", ">="})
IDENTIFIER = re.compile(r"[A-Za-z_][\w{}@]*")


def search_commands(query: ParsedQuery) -> Iterator[Command]:
    """Commands whose arguments use search syntax (base searches and | search)."""
    return query.commands("search")


def base_searches(query: ParsedQuery) -> Iterator[Command]:
    """The first command of each pipeline, when it is a search."""
    for pipeline in query.pipelines():
        if pipeline.commands and pipeline.commands[0].name == "search":
            first = pipeline.commands[0]
            if pipeline.owner is None or pipeline.owner.name not in ("appendpipe", "foreach"):
                yield first


def eval_commands(query: ParsedQuery) -> Iterator[Command]:
    return query.commands("eval", "where", "fieldformat")


def prev_tok(tokens: List[Token], i: int) -> Optional[Token]:
    return tokens[i - 1] if i > 0 else None


def next_tok(tokens: List[Token], i: int) -> Optional[Token]:
    return tokens[i + 1] if i + 1 < len(tokens) else None


def eval_assignments(cmd: Command) -> Set[int]:
    """Indices of assignment targets in `eval a=..., b=...` (not comparisons)."""
    if cmd.name not in ("eval", "fieldformat"):
        return set()
    targets: Set[int] = set()
    depth = 0
    segment_start = 0
    assigned = False
    for i, tok in enumerate(cmd.tokens()):
        if tok.kind == LPAREN:
            depth += 1
        elif tok.kind == RPAREN:
            depth -= 1
        elif depth == 0 and tok.kind == COMMA:
            segment_start, assigned = i + 1, False
        elif depth == 0 and not assigned and tok.kind == OP and tok.value == "=":
            targets.update(range(segment_start, i))
            assigned = True
    return targets


def call_args(tokens: List[Token], lparen: int) -> Tuple[List[List[Token]], int]:
    """Split the arguments of the call whose '(' is at tokens[lparen]."""
    args: List[List[Token]] = [[]]
    depth = 0
    for j in range(lparen, len(tokens)):
        tok = tokens[j]
        if tok.kind == LPAREN:
            depth += 1
            if depth == 1:
                continue
        elif tok.kind == RPAREN:
            depth -= 1
            if depth == 0:
                return args, j
        elif tok.kind == COMMA and depth == 1:
            args.append([])
            continue
        args[-1].append(tok)
    return args, len(tokens) - 1


def is_op(tok: Optional[Token], *values: str) -> bool:
    return tok is not None and tok.kind == OP and (not values or tok.value in values)
