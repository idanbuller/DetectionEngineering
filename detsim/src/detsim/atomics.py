"""Match a detection to specific Atomic Red Team test GUIDs.

A technique usually has several atomic tests; only some of them exercise the exact behavior a
given rule looks for. We index the Atomic Red Team repo by technique, then score each test in
the rule's technique(s) by how many of the rule's own match-literals (certutil, urlcache,
/priv, ...) appear in the test's command/name. The best-scoring tests are the ones most likely
to actually trip the rule.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import yaml

from .predicate import And, Cmp, Node, Not, Or, Term

_TOKEN = re.compile(r"[A-Za-z0-9][\w./-]{2,}")


@dataclass
class AtomicTest:
    technique: str
    guid: str
    name: str
    platforms: List[str]
    blob: str  # lowercased command + name + description, for matching
    name_blob: str = ""  # lowercased name, weighted higher (most specific signal)

    def command(self) -> str:
        return f"Invoke-AtomicTest {self.technique} -TestGuids {self.guid}"


def load_index(path: str) -> Dict[str, List[AtomicTest]]:
    """Index an Atomic Red Team clone (its `atomics/` dir) by technique id."""
    atomics_dir = os.path.join(path, "atomics") if os.path.isdir(os.path.join(path, "atomics")) else path
    has_techniques = os.path.isdir(atomics_dir) and any(
        d.startswith("T") and os.path.isdir(os.path.join(atomics_dir, d)) for d in os.listdir(atomics_dir)
    )
    if not has_techniques:
        raise FileNotFoundError(f"{path}: not an Atomic Red Team checkout (no atomics/T*/ folders)")
    index: Dict[str, List[AtomicTest]] = {}
    for tech in sorted(os.listdir(atomics_dir)):
        yml = os.path.join(atomics_dir, tech, f"{tech}.yaml")
        if not (tech.startswith("T") and os.path.isfile(yml)):
            continue
        try:
            with open(yml, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            continue
        for test in (data or {}).get("atomic_tests", []) or []:
            guid = test.get("auto_generated_guid")
            if not guid:
                continue
            command = ((test.get("executor") or {}).get("command")) or ""
            blob = " ".join(str(x) for x in (test.get("name", ""), test.get("description", ""), command)).lower()
            index.setdefault(tech, []).append(
                AtomicTest(
                    tech,
                    str(guid),
                    str(test.get("name", "")),
                    test.get("supported_platforms") or [],
                    blob,
                    str(test.get("name", "")).lower(),
                )
            )
    return index


def literals(node: Node, out: Optional[List[str]] = None) -> List[str]:
    """The distinctive strings a rule keys on, from positive comparisons and keywords."""
    if out is None:
        out = []
    if isinstance(node, And):
        for n in node.nodes:
            literals(n, out)
    elif isinstance(node, Or):
        for n in node.nodes:
            literals(n, out)
    elif isinstance(node, Not):
        return out  # exclusions don't describe the behavior to simulate
    elif isinstance(node, Cmp):
        if node.op not in ("!=",) and node.field.lower() not in ("index", "sourcetype", "source", "eventcode"):
            for tok in _TOKEN.findall(node.value.replace("*", " ")):
                out.append(tok.lower())
    elif isinstance(node, Term):
        out += [t.lower() for t in _TOKEN.findall(node.text)]
    return out


@dataclass
class Match:
    test: AtomicTest
    score: int


def match(techniques: List[str], rule_literals: List[str], index: Dict[str, List[AtomicTest]]) -> List[Match]:
    """Candidate atomic tests for a detection, best first."""
    wanted = {lit for lit in rule_literals if len(lit) >= 3}
    seen: set = set()
    candidates: List[Match] = []
    for tech in techniques:
        for test in index.get(tech, []):
            if test.guid in seen:
                continue
            seen.add(test.guid)
            # literals in the test's name are the strongest signal, so weight them higher
            score = sum(1 for lit in wanted if lit in test.blob) + 2 * sum(1 for lit in wanted if lit in test.name_blob)
            candidates.append(Match(test, score))
    candidates.sort(key=lambda m: (-m.score, m.test.name))
    return candidates
