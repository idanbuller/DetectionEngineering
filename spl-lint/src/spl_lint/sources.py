"""Find SPL queries in files and map query offsets back to file positions.

Supported inputs:
  *.spl                 the whole file is one query
  *.yml / *.yaml        every string value under a configured key (search, spl, query)
  savedsearches.conf    the `search = ...` setting of every stanza
"""

from __future__ import annotations

import bisect
import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

import yaml

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", "build", "dist"}


@dataclass
class QuerySource:
    path: str
    text: str
    name: Optional[str] = None  # detection / stanza name, when known
    # (query offset, 1-based file line, 1-based file column) for the start of each query line
    line_map: List[Tuple[int, int, int]] = field(default_factory=list)

    def position(self, offset: int) -> Tuple[int, int]:
        if not self.line_map:
            return 1, offset + 1
        idx = bisect.bisect_right([m[0] for m in self.line_map], offset) - 1
        q_off, line, col = self.line_map[max(idx, 0)]
        return line, col + (offset - q_off)

    def line_text(self, offset: int) -> Tuple[str, int]:
        """The query line containing offset, and offset's column within it."""
        start = self.text.rfind("\n", 0, offset) + 1
        end = self.text.find("\n", offset)
        return self.text[start : end if end != -1 else len(self.text)], offset - start


def line_map(text: str, first_line: int, first_col: int, col: int) -> List[Tuple[int, int, int]]:
    """Map for text whose first line starts at (first_line, first_col) and later lines at col."""
    out = []
    offset = 0
    for i, line in enumerate(text.split("\n")):
        out.append((offset, first_line + i, first_col if i == 0 else col))
        offset += len(line) + 1
    return out


# -- .spl ---------------------------------------------------------------------


def read_spl(path: str, content: str) -> List[QuerySource]:
    return [QuerySource(path, content, None, line_map(content, 1, 1, 1))]


# -- YAML -----------------------------------------------------------------------


def read_yaml(path: str, content: str, keys: Sequence[str]) -> List[QuerySource]:
    lines = content.split("\n")
    out: List[QuerySource] = []
    for doc in yaml.compose_all(content, Loader=yaml.SafeLoader):
        if doc is not None:
            _walk_yaml(doc, path, lines, set(keys), None, out)
    return out


def _walk_yaml(node, path, lines, keys, name, out):
    if isinstance(node, yaml.MappingNode):
        name = _mapping_name(node) or name
        for key_node, value_node in node.value:
            if (
                isinstance(key_node, yaml.ScalarNode)
                and key_node.value in keys
                and isinstance(value_node, yaml.ScalarNode)
                and value_node.tag == "tag:yaml.org,2002:str"
                and value_node.value.strip()
            ):
                out.append(_yaml_source(value_node, path, lines, name))
            else:
                _walk_yaml(value_node, path, lines, keys, name, out)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _walk_yaml(item, path, lines, keys, name, out)


def _mapping_name(node) -> Optional[str]:
    for key_node, value_node in node.value:
        if (
            isinstance(key_node, yaml.ScalarNode)
            and key_node.value in ("name", "title")
            and isinstance(value_node, yaml.ScalarNode)
        ):
            return value_node.value
    return None


def _yaml_source(node, path, lines, name) -> QuerySource:
    text = node.value
    mark = node.start_mark
    if node.style in ("|", ">"):
        # Content starts on the line after the indicator; find its indentation.
        first = mark.line + 1
        while first < len(lines) and not lines[first].strip():
            first += 1
        indent = len(lines[first]) - len(lines[first].lstrip(" ")) if first < len(lines) else 0
        if node.style == "|":
            lm = line_map(text, mark.line + 2, indent + 1, indent + 1)
        else:  # folded: lines are joined, so only the first line maps exactly
            lm = [(0, first + 1, indent + 1)]
    else:
        quote = 1 if node.style in ('"', "'") else 0
        lm = line_map(text, mark.line + 1, mark.column + 1 + quote, 1)
        if "\n" in text:
            lm = lm[:1]  # multi-line flow scalars are re-flowed by YAML; keep the start
    return QuerySource(path, text, name, lm)


# -- savedsearches.conf ----------------------------------------------------------

_STANZA = re.compile(r"^\s*\[(.+)\]\s*$")
_SEARCH_KEY = re.compile(r"^(\s*search\s*=\s*)(.*)$")


def read_savedsearches(path: str, content: str) -> List[QuerySource]:
    out: List[QuerySource] = []
    lines = content.split("\n")
    stanza: Optional[str] = None
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _STANZA.match(line)
        if m:
            stanza = m.group(1)
            i += 1
            continue
        m = _SEARCH_KEY.match(line)
        if not m:
            i += 1
            continue
        parts: List[str] = []
        lm: List[Tuple[int, int, int]] = []
        offset = 0
        col = len(m.group(1)) + 1
        value = m.group(2)
        while True:
            continued = value.endswith("\\")
            if continued:
                value = value[:-1]
            lm.append((offset, i + 1, col))
            parts.append(value)
            offset += len(value) + 1
            if not continued or i + 1 >= len(lines):
                break
            i += 1
            value, col = lines[i], 1
        text = "\n".join(parts)
        if text.strip():
            out.append(QuerySource(path, text, stanza, lm))
        i += 1
    return out


# -- discovery -------------------------------------------------------------------


def is_supported(path: str) -> bool:
    base = os.path.basename(path)
    return base.endswith((".spl", ".yml", ".yaml")) or base == "savedsearches.conf"


def iter_files(paths: Iterable[str], exclude: Sequence[str] = ()) -> Iterator[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
                for f in sorted(files):
                    full = os.path.join(root, f)
                    if is_supported(full) and not _excluded(full, exclude):
                        yield full
        elif not _excluded(p, exclude):
            yield p  # explicit files are always read, whatever their extension


def _excluded(path: str, patterns: Sequence[str]) -> bool:
    norm = os.path.normpath(path)
    return any(fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(os.path.basename(norm), p) for p in patterns)


def read_sources(path: str, content: str, yaml_keys: Sequence[str]) -> List[QuerySource]:
    base = os.path.basename(path)
    if base.endswith((".yml", ".yaml")):
        return read_yaml(path, content, yaml_keys)
    if base.endswith(".conf"):
        return read_savedsearches(path, content)
    return read_spl(path, content)
