"""Synthesize an event that trips a detection, from its parsed predicate.

Approach: walk the AST collecting the positive constraints that make it true (satisfy every
AND, one branch of each OR, and skip NOT subtrees so their exclusions stay false). Per field,
build a value meeting all its constraints, then self-check the event against the AST with the
matcher. If the check fails (a contradiction we couldn't resolve), the detection is reported
as needing manual simulation instead of emitting a wrong event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .predicate import And, Cmp, Node, Not, Or, Predicate, Term, matches


class Unsatisfiable(ValueError):
    pass


@dataclass
class Synth:
    event: Dict[str, Any]
    keywords: List[str] = field(default_factory=list)


def _collect(node: Node, cons: Dict[str, List[Cmp]], keywords: List[str]) -> None:
    if isinstance(node, And):
        for n in node.nodes:
            _collect(n, cons, keywords)
    elif isinstance(node, Or):
        # satisfy the first branch that isn't a pure negation
        chosen = next((n for n in node.nodes if not isinstance(n, Not)), node.nodes[0])
        _collect(chosen, cons, keywords)
    elif isinstance(node, Not):
        return  # leave the excluded fields unset so the NOT stays satisfied
    elif isinstance(node, Cmp):
        if node.op in ("!=",):
            return
        cons.setdefault(node.field, []).append(node)
    elif isinstance(node, Term):
        keywords.append(node.text.strip('"'))


def _value_for(field_name: str, cmps: List[Cmp]) -> Any:
    numeric = [c for c in cmps if c.numeric or c.op in ("<", "<=", ">", ">=")]
    if numeric:
        return _numeric_value(numeric)
    exacts = [c.value for c in cmps if not c.wildcard and c.value != "*"]
    if exacts:
        chosen = exacts[0]
        for c in cmps:  # every other constraint must be compatible with the exact value
            if not _satisfies(chosen, c):
                raise Unsatisfiable(f"conflicting constraints on {field_name}")
        return chosen
    # build from wildcard patterns: keep prefixes first, suffixes last, contains in the middle
    lead, mids, trail = "", [], ""
    only_exists = True
    for c in cmps:
        pat = c.value
        if pat == "*":
            continue
        only_exists = False
        segs = [s for s in pat.split("*") if s]
        if not segs:
            continue
        if not pat.startswith("*"):  # anchored start
            lead = segs[0]
            mids += segs[1:-1] if len(segs) > 2 else segs[1:] if len(segs) > 1 else []
            if len(segs) > 1 and not pat.endswith("*"):
                trail = segs[-1]
        elif not pat.endswith("*"):  # anchored end only
            trail = segs[-1]
            mids += segs[:-1]
        else:  # contains
            mids += segs
    if only_exists and not lead and not mids and not trail:
        return f"sim-{field_name}"
    value = lead + "".join(m for m in mids if m not in lead) + trail
    return value or f"sim-{field_name}"


def _numeric_value(cmps: List[Cmp]) -> int:
    lo, hi = None, None
    for c in cmps:
        n = float(c.value)
        if c.op in (">", ">="):
            lo = max(lo, n + (1 if c.op == ">" else 0)) if lo is not None else n + (1 if c.op == ">" else 0)
        elif c.op in ("<", "<="):
            hi = min(hi, n - (1 if c.op == "<" else 0)) if hi is not None else n - (1 if c.op == "<" else 0)
        else:
            return int(n)
    if lo is not None and hi is not None and lo > hi:
        raise Unsatisfiable("conflicting numeric bounds")
    chosen = lo if lo is not None else (hi if hi is not None else 1)
    return int(chosen)


def _satisfies(value: str, c: Cmp) -> bool:
    import fnmatch

    if c.value == "*":
        return True
    if c.wildcard and "*" in c.value:
        return fnmatch.fnmatchcase(value.lower(), c.value.lower())
    return value.lower() == c.value.lower()


def synthesize(predicate: Predicate) -> Synth:
    cons: Dict[str, List[Cmp]] = {}
    keywords: List[str] = []
    _collect(predicate.ast, cons, keywords)

    event: Dict[str, Any] = {}
    for field_name, cmps in cons.items():
        event[field_name] = _value_for(field_name, cmps)
    if keywords:
        event["_raw"] = " ".join(keywords)

    if not matches(predicate.ast, event):
        raise Unsatisfiable("could not build an event satisfying the detection automatically")
    return Synth(event=event, keywords=keywords)
