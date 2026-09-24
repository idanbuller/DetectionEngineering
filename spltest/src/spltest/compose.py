"""Rewrite a detection so it runs on inline synthetic data instead of an index.

    index=os sourcetype=linux_secure "Failed password" earliest=-15m | stats ...
becomes
    | makeresults format=json data="..."        <- the synthlog dataset
    | search index=os sourcetype=linux_secure "Failed password" | stats ...

Every synthetic event carries index, sourcetype, source and host, so the base
search terms filter the inline data exactly as they would filter an index.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

from spl_lint.parser import OP, WORD, parse

# Time modifiers would filter the synthetic timeline against "now"; the dataset defines the time range.
TIME_MODIFIERS = frozenset(
    {"earliest", "latest", "_index_earliest", "_index_latest", "starttime", "endtime", "starttimeu", "endtimeu"}
)
_CONTINUATIONS = ("appendpipe", "foreach")


class ComposeError(ValueError):
    pass


@dataclass
class Composed:
    search: str
    notes: List[str] = field(default_factory=list)


def expand_macros(spl: str, macros: Dict[str, str]) -> str:
    """Replace `name` or `name(args)` with the given definitions, recursively."""
    if not macros:
        return spl
    for _ in range(10):
        changed = False
        for name, definition in macros.items():
            key = name if name.startswith("`") else f"`{name}`"
            if key in spl:
                spl = spl.replace(key, definition)
                changed = True
        if not changed:
            return spl
    raise ComposeError("macro expansion did not settle after 10 rounds (a macro that includes itself?)")


def compose(detection_spl: str, data_search: str, macros: Dict[str, str]) -> Composed:
    spl = expand_macros(detection_spl.strip(), macros)
    query = parse(spl)
    if query.diagnostics:
        d = query.diagnostics[0]
        raise ComposeError(f"the detection doesn't parse: {d.message} at offset {d.start}")
    root = query.root
    if not root.commands:
        raise ComposeError("the detection is empty")
    first = root.commands[0]
    if root.leading_pipe or first.name != "search":
        raise ComposeError(
            f"the detection starts with | {first.name or first.raw_name}; only detections that start with a "
            "base search can run on inline data (for tstats/datamodel searches, test the underlying raw search)"
        )

    notes: List[str] = []
    cut = []
    tokens = first.tokens()
    for i, tok in enumerate(tokens):
        if (
            tok.kind == WORD
            and tok.value.lower() in TIME_MODIFIERS
            and i + 2 < len(tokens)
            and tokens[i + 1].kind == OP
            and tokens[i + 1].value == "="
        ):
            cut.append((tok.start, tokens[i + 2].end))
            notes.append(
                f"removed time modifier {spl[tok.start : tokens[i + 2].end]} (the dataset sets the time range)"
            )

    base = spl[first.args_start : first.end]
    for start, end in sorted(cut, reverse=True):
        a, b = start - first.args_start, end - first.args_start
        base = base[:a] + base[b:]
    base = re.sub(r"[ \t]{2,}", " ", base).strip()
    rest = spl[first.end :]

    for pipeline in query.pipelines():
        owner = pipeline.owner
        if owner is None or owner.name in _CONTINUATIONS or not pipeline.commands:
            continue
        head = pipeline.commands[0]
        if head.name == "search" or head.name in ("tstats", "datamodel", "from"):
            snippet = spl[pipeline.start : min(pipeline.end, pipeline.start + 60)].strip()
            notes.append(f"a subsearch reads real indexed data, not the test dataset: [{snippet}...]")

    search = f"{data_search}\n| search {base}{rest}" if base else f"{data_search}{rest}"
    return Composed(search, notes)
