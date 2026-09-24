"""Load *.test.yml files.

name: SSH brute force                        # optional
detection: ../detections/ssh_bruteforce.yml  # a YAML detection (search: key) or a .spl file
search: index=os ... | stats ...             # ...or the SPL inline
dataset: ../datasets/corp.yml                # a synthlog spec
background: false                            # false (default) | true | a duration such as 2h
sources: [linux_auth]                        # optional: only inline these dataset sources
macros: {sysmon: "index=edr sourcetype=sysmon"}   # optional overrides
max_unexpected: 0                            # optional: fail on rows no scenario explains
expect:
  - scenario: ssh_bruteforce
    match: {src: "{attacker.ip}", user: "{user.name}"}
  - scenario: admin_password_typos           # benign scenarios must not fire by default
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

import yaml
from spl_lint.sources import QuerySource, line_map, read_sources

TEST_SUFFIXES = (".test.yml", ".test.yaml")


class SpecFileError(ValueError):
    pass


@dataclass
class Expectation:
    scenario: str
    fires: Optional[bool]  # None: decided by the scenario's label
    match: Dict[str, str]
    instances: str = "all"  # all | any: how many runs of a repeated scenario must behave


@dataclass
class DetectionTest:
    path: str
    name: str
    search: str
    detection_path: Optional[str]
    dataset_path: str
    background: Union[bool, str]
    sources: Optional[List[str]]
    macros: Dict[str, str]
    max_unexpected: Optional[int]
    expect: List[Expectation] = field(default_factory=list)
    source: Optional[QuerySource] = None  # where the SPL came from, for mapping lint findings to lines


def discover(paths: List[str]) -> List[str]:
    found = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv"))
                found += [os.path.join(root, f) for f in sorted(files) if f.endswith(TEST_SUFFIXES)]
        else:
            found.append(p)
    return found


def _resolve(base: str, rel: str) -> str:
    return rel if os.path.isabs(rel) else os.path.normpath(os.path.join(os.path.dirname(base), rel))


def _read_detection(path: str) -> QuerySource:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    sources = read_sources(path, content, ["search", "spl", "query"])
    if not sources:
        raise SpecFileError(f"{path}: no search found (expected a search: key or a .spl file)")
    if len(sources) > 1:
        raise SpecFileError(f"{path}: contains {len(sources)} searches; point the test at a file with one")
    return sources[0]


def load_test(path: str) -> DetectionTest:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise SpecFileError(f"{path}: invalid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise SpecFileError(f"{path}: expected a mapping")
    allowed = {"name", "detection", "search", "dataset", "background", "sources", "macros", "max_unexpected", "expect"}
    unknown = set(data) - allowed
    if unknown:
        raise SpecFileError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")

    if ("detection" in data) == ("search" in data):
        raise SpecFileError(f"{path}: set exactly one of detection: (a file) or search: (inline SPL)")
    detection_path = None
    if "detection" in data:
        detection_path = _resolve(path, str(data["detection"]))
        source = _read_detection(detection_path)
    else:
        text = str(data["search"])
        source = QuerySource(path, text, None, line_map(text, 1, 1, 1))

    if "dataset" not in data:
        raise SpecFileError(f"{path}: dataset: (a synthlog spec) is required")
    background = data.get("background", False)
    if not isinstance(background, (bool, str)):
        raise SpecFileError(f"{path}: background must be true, false or a duration such as 2h")

    sources = data.get("sources")
    if isinstance(sources, str):
        sources = [sources]
    if sources is not None and not (isinstance(sources, list) and all(isinstance(s, str) for s in sources)):
        raise SpecFileError(f"{path}: sources must be a list of dataset source names")

    macros = data.get("macros") or {}
    if not isinstance(macros, dict):
        raise SpecFileError(f"{path}: macros must be a mapping of name to definition")

    max_unexpected = data.get("max_unexpected")
    if max_unexpected is not None and (not isinstance(max_unexpected, int) or max_unexpected < 0):
        raise SpecFileError(f"{path}: max_unexpected must be a non-negative integer")

    expect_data = data.get("expect")
    if not isinstance(expect_data, list) or not expect_data:
        raise SpecFileError(f"{path}: expect: must list at least one scenario")
    expect = []
    for i, item in enumerate(expect_data):
        where = f"{path}: expect[{i}]"
        if isinstance(item, str):
            item = {"scenario": item}
        if not isinstance(item, dict) or "scenario" not in item:
            raise SpecFileError(f"{where}: needs a scenario id")
        extra = set(item) - {"scenario", "fires", "match", "instances"}
        if extra:
            raise SpecFileError(f"{where}: unknown key(s): {', '.join(sorted(extra))}")
        fires = item.get("fires")
        if fires is not None and not isinstance(fires, bool):
            raise SpecFileError(f"{where}: fires must be true or false")
        match = item.get("match") or {}
        if not isinstance(match, dict):
            raise SpecFileError(f"{where}: match must map result fields to expected values")
        instances = item.get("instances", "all")
        if instances not in ("all", "any"):
            raise SpecFileError(f"{where}: instances must be all or any")
        expect.append(Expectation(str(item["scenario"]), fires, {str(k): str(v) for k, v in match.items()}, instances))

    name = str(data.get("name") or source.name or os.path.basename(path))
    return DetectionTest(
        path=path,
        name=name,
        search=source.text,
        detection_path=detection_path,
        dataset_path=_resolve(path, str(data["dataset"])),
        background=background,
        sources=sources,
        macros={str(k): str(v) for k, v in macros.items()},
        max_unexpected=max_unexpected,
        expect=expect,
        source=source,
    )
