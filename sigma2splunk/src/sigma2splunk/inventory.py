"""Which index/sourcetype pairs your environment actually collects.

Accepts the same file shapes as detcov's health file, so one inventory serves both tools:
  * a list of {index, sourcetype} (or {index})
  * a mapping {"index::sourcetype": {...}} or {"index": {...}}
  * a plain list of index names
"""

from __future__ import annotations

from typing import Optional, Set, Tuple

import yaml


class Inventory:
    def __init__(self, pairs: Set[Tuple[str, Optional[str]]]) -> None:
        self._pairs = pairs
        self._indexes = {i for i, _ in pairs}

    def available(self, index: Optional[str], sourcetype: Optional[str]) -> bool:
        if index is None:
            return True  # nothing to check against; don't filter it out
        if (index, sourcetype) in self._pairs:
            return True
        if sourcetype is not None and (index, None) in self._pairs:
            return True
        return index in self._indexes

    def __bool__(self) -> bool:
        return bool(self._pairs)


def load_inventory(path: str) -> Inventory:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    pairs: Set[Tuple[str, Optional[str]]] = set()
    if isinstance(data, dict):
        for key in data:
            index, _, sourcetype = str(key).partition("::")
            if index:
                pairs.add((index, sourcetype or None))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                pairs.add((item, None))
            elif isinstance(item, dict) and item.get("index"):
                pairs.add((str(item["index"]), str(item["sourcetype"]) if item.get("sourcetype") else None))
    else:
        raise ValueError(f"{path}: expected a list or mapping of index/sourcetype")
    # also register index-level availability so a rule with an unmapped sourcetype still matches
    for index in {i for i, _ in pairs}:
        pairs.add((index, None))
    return Inventory(pairs)
