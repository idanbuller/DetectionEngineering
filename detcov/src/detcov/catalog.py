"""Load a detection catalog and work out which ATT&CK techniques and data each rule covers.

A detection is any .yml/.yaml with a search (a `search`, `spl`, or `query` key) or a
bare .spl file. Techniques come from a `mitre`/`mitre_attack`/`techniques` field, or the
`technique` key, or a `Txxxx[.xxx]` in the file name. The index/sourcetype a rule needs are
read straight from its SPL with spl-lint's parser, so coverage tracks what the rule really
queries rather than a hand-maintained field.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

import yaml
from spl_lint.parser import LPAREN, RPAREN, STRING, WORD, parse
from spl_lint.sources import read_sources

TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?(?!\d)")
_TECHNIQUE_KEYS = ("mitre", "mitre_attack", "mitre_technique", "mitre_techniques", "techniques", "technique", "attack")
DataPair = Tuple[str, Optional[str]]  # (index, sourcetype); sourcetype None = index-level only


@dataclass
class Detection:
    path: str
    name: str
    techniques: List[str]
    search: str
    indexes: Set[str] = field(default_factory=set)
    sourcetypes: Set[str] = field(default_factory=set)
    uses_macro_index: bool = False  # index likely comes from a macro; data can't be resolved from SPL

    @property
    def data_pairs(self) -> Set[DataPair]:
        if not self.indexes:
            return set()
        if not self.sourcetypes:
            return {(i, None) for i in self.indexes}
        return {(i, s) for i in self.indexes for s in self.sourcetypes}


class CatalogError(ValueError):
    pass


def _terms(search: str, keyword: str) -> Tuple[Set[str], bool]:
    """Values of `keyword=...` and `keyword IN (...)` across search/tstats commands.

    Returns (values, saw_macro) where saw_macro means a macro appeared in a base search and
    may be supplying the value.
    """
    values: Set[str] = set()
    saw_macro = False
    query = parse(search)
    for cmd in query.commands():
        if cmd.name not in ("search", "tstats", "mstats", "from"):
            continue
        tokens = cmd.tokens()
        for i, tok in enumerate(tokens):
            if tok.kind == "MACRO":
                saw_macro = True
            if tok.kind == WORD and tok.value.lower() == keyword:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                if nxt and nxt.kind == "OP" and nxt.value in ("=", "=="):
                    val = tokens[i + 2] if i + 2 < len(tokens) else None
                    if val and val.kind in (WORD, STRING):
                        values.add(val.value)
                elif nxt and nxt.kind == WORD and nxt.value.upper() == "IN":
                    j = i + 2
                    if j < len(tokens) and tokens[j].kind == LPAREN:
                        j += 1
                        while j < len(tokens) and tokens[j].kind != RPAREN:
                            if tokens[j].kind in (WORD, STRING):
                                values.add(tokens[j].value)
                            j += 1
    return {v for v in values if v and v != "*"}, saw_macro


def extract_data(search: str) -> Tuple[Set[str], Set[str], bool]:
    indexes, macro_i = _terms(search, "index")
    sourcetypes, macro_s = _terms(search, "sourcetype")
    return indexes, sourcetypes, (macro_i or macro_s) and not indexes


def _techniques_from_data(data: dict) -> List[str]:
    found: List[str] = []
    for key in _TECHNIQUE_KEYS:
        if key in data:
            val = data[key]
            items = val if isinstance(val, list) else [val]
            for item in items:
                found += TECHNIQUE.findall(str(item))
    # also scan a `tags:` list, where techniques often hide as attack.t1059.001
    tags = data.get("tags")
    if isinstance(tags, (list, dict)):
        found += TECHNIQUE.findall(" ".join(map(str, tags if isinstance(tags, list) else tags)).upper())
    return found


def load_detection(path: str) -> List[Detection]:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    sources = read_sources(path, content, ["search", "spl", "query"])
    if not sources:
        return []
    techniques = []
    if path.endswith((".yml", ".yaml")):
        try:
            for doc in yaml.safe_load_all(content):
                if isinstance(doc, dict):
                    techniques += _techniques_from_data(doc)
        except yaml.YAMLError as exc:
            raise CatalogError(f"{path}: invalid YAML: {exc}") from None
    techniques += TECHNIQUE.findall(os.path.basename(path).upper())
    techniques = sorted(set(t.upper() for t in techniques))

    detections = []
    for src in sources:
        indexes, sourcetypes, macro = extract_data(src.text)
        detections.append(
            Detection(
                path=path,
                name=src.name or os.path.basename(path),
                techniques=techniques,
                search=src.text,
                indexes=indexes,
                sourcetypes=sourcetypes,
                uses_macro_index=macro,
            )
        )
    return detections


def load_catalog(paths: List[str]) -> List[Detection]:
    detections: List[Detection] = []
    for path in _discover(paths):
        detections += load_detection(path)
    return detections


def _discover(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv"))
                out += [
                    os.path.join(root, f)
                    for f in sorted(files)
                    if f.endswith((".yml", ".yaml", ".spl")) and not f.endswith((".test.yml", ".case.yml"))
                ]
        else:
            out.append(p)
    return out
