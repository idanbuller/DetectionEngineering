"""Load validation-case files (*.case.yml).

A case ties an ATT&CK technique to a way of executing it and the SIEM signal(s)
that should appear afterwards:

    technique: T1059.001
    name: Encoded PowerShell from Office
    tactic: execution
    authorized: false            # you must set this true, per case, to allow real execution
    execute:
      executor: atomic           # dryrun (default) | manual | command | atomic
      atomic_guid: 3c73d728-...  # a test in the public Atomic Red Team repo (payload lives there)
      input_args: {output_file: C:\\Windows\\Temp\\t.txt}
      target: canary-01          # informational; SSH target for command/atomic when ssh: is set
      ssh: operator@canary-01    # optional: run the command/atomic over SSH
    expect:
      - name: EDR sees encoded powershell
        kind: telemetry          # telemetry | notable | risk
        search: |
          index=edr sourcetype=edr:process
          | spath | search process_name=powershell.exe cmdline="*-enc*"
        min_rows: 1
        match: {dest: "{target}"}
        window: 15m              # search this far after execution
        settle: 60s             # wait before the first check
        poll: 30s               # re-check interval until the window is up

Nothing in a case file is executed by loading it. Payloads are never stored here;
the `atomic` executor references Atomic Red Team by GUID, and `command` runs a
command you wrote yourself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

import yaml

CASE_SUFFIXES = (".case.yml", ".case.yaml")
EXECUTORS = ("dryrun", "manual", "command", "atomic")
CHECK_KINDS = ("telemetry", "notable", "risk")
_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}


class CaseError(ValueError):
    pass


def parse_duration(value, path: str) -> timedelta:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return timedelta(seconds=float(value))
    import re

    text = str(value).replace(" ", "")
    seconds, pos = 0.0, 0
    for m in re.finditer(r"(\d+(?:\.\d+)?)(ms|s|m|h|d)", text):
        if m.start() != pos:
            break
        seconds += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    if not text or pos != len(text):
        raise CaseError(f"{path}: invalid duration {value!r} (examples: 30s, 5m, 1h)")
    return timedelta(seconds=seconds)


@dataclass
class Execute:
    executor: str
    atomic_guid: Optional[str]
    atomic_test: Optional[str]  # a test number/name, when a GUID isn't used
    command: Optional[str]
    input_args: Dict[str, str]
    target: Optional[str]
    ssh: Optional[str]
    cleanup: Optional[str]


@dataclass
class Check:
    name: str
    kind: str
    search: str
    min_rows: int
    match: Dict[str, str]
    window: timedelta
    settle: timedelta
    poll: timedelta


@dataclass
class Case:
    path: str
    technique: str
    name: str
    tactic: Optional[str]
    description: str
    authorized: bool
    execute: Execute
    expect: List[Check] = field(default_factory=list)


def discover(paths: List[str]) -> List[str]:
    found: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv"))
                found += [os.path.join(root, f) for f in sorted(files) if f.endswith(CASE_SUFFIXES)]
        else:
            found.append(p)
    return found


def _check_keys(data: Dict, allowed: set, path: str, what: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise CaseError(f"{path}: unknown key(s) in {what}: {', '.join(sorted(map(str, unknown)))}")


def _parse_execute(data, path: str) -> Execute:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise CaseError(f"{path}: execute must be a mapping")
    _check_keys(
        data,
        {"executor", "atomic_guid", "atomic_test", "command", "input_args", "target", "ssh", "cleanup"},
        path,
        "execute",
    )
    executor = str(data.get("executor", "dryrun"))
    if executor not in EXECUTORS:
        raise CaseError(f"{path}: executor must be one of {', '.join(EXECUTORS)}")
    args = data.get("input_args") or {}
    if not isinstance(args, dict):
        raise CaseError(f"{path}: input_args must be a mapping")
    if executor == "command" and not data.get("command"):
        raise CaseError(f"{path}: the command executor needs a command:")
    if executor == "atomic" and not (data.get("atomic_guid") or data.get("atomic_test")):
        raise CaseError(f"{path}: the atomic executor needs atomic_guid: (or atomic_test:)")
    return Execute(
        executor=executor,
        atomic_guid=_opt_str(data.get("atomic_guid")),
        atomic_test=_opt_str(data.get("atomic_test")),
        command=_opt_str(data.get("command")),
        input_args={str(k): str(v) for k, v in args.items()},
        target=_opt_str(data.get("target")),
        ssh=_opt_str(data.get("ssh")),
        cleanup=_opt_str(data.get("cleanup")),
    )


def _opt_str(v) -> Optional[str]:
    return None if v is None else str(v)


def _parse_check(data, path: str, i: int) -> Check:
    where = f"{path}: expect[{i}]"
    if not isinstance(data, dict):
        raise CaseError(f"{where}: must be a mapping")
    _check_keys(data, {"name", "kind", "search", "min_rows", "match", "window", "settle", "poll"}, where, "check")
    if not data.get("search"):
        raise CaseError(f"{where}: needs a search")
    kind = str(data.get("kind", "telemetry"))
    if kind not in CHECK_KINDS:
        raise CaseError(f"{where}: kind must be one of {', '.join(CHECK_KINDS)}")
    min_rows = data.get("min_rows", 1)
    if not isinstance(min_rows, int) or min_rows < 1:
        raise CaseError(f"{where}: min_rows must be a positive integer")
    match = data.get("match") or {}
    if not isinstance(match, dict):
        raise CaseError(f"{where}: match must be a mapping of field to expected value")
    return Check(
        name=str(data.get("name", f"{kind} check {i + 1}")),
        kind=kind,
        search=str(data["search"]).strip(),
        min_rows=min_rows,
        match={str(k): str(v) for k, v in match.items()},
        window=parse_duration(data.get("window", "15m"), f"{where}.window"),
        settle=parse_duration(data.get("settle", "60s"), f"{where}.settle"),
        poll=parse_duration(data.get("poll", "30s"), f"{where}.poll"),
    )


def load_case(path: str) -> Case:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise CaseError(f"{path}: invalid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise CaseError(f"{path}: expected a mapping")
    _check_keys(
        data,
        {"technique", "name", "tactic", "description", "authorized", "execute", "expect"},
        path,
        "case",
    )
    if "technique" not in data:
        raise CaseError(f"{path}: a case needs a technique (e.g. T1059.001)")
    expect_data = data.get("expect")
    if not isinstance(expect_data, list) or not expect_data:
        raise CaseError(f"{path}: expect: must list at least one SIEM check")
    authorized = data.get("authorized", False)
    if not isinstance(authorized, bool):
        raise CaseError(f"{path}: authorized must be true or false")
    return Case(
        path=path,
        technique=str(data["technique"]),
        name=str(data.get("name") or os.path.basename(path)),
        tactic=_opt_str(data.get("tactic")),
        description=str(data.get("description", "")),
        authorized=authorized,
        execute=_parse_execute(data.get("execute"), path),
        expect=[_parse_check(c, path, i) for i, c in enumerate(expect_data)],
    )
