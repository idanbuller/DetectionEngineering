"""Run (or decline to run) the technique described by a case.

Safety model
------------
detval never contains attack payloads. It either:
  * dryrun   - runs nothing; the verification step still runs (default).
  * manual   - prints steps for a human to run, and records when they confirm.
  * command  - runs a command you wrote in the case file.
  * atomic   - invokes your local Atomic Red Team runner (Invoke-AtomicTest) by
               test GUID; the payload lives in the Atomic Red Team repo you
               installed, not here.

command and atomic actually execute code. They run only when BOTH are true:
  * the case sets `authorized: true`, and
  * the caller passed allow_execution=True (the CLI's --allow-execution).
Otherwise they behave like dryrun and say why.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from .casespec import Case, Execute

EXECUTED, SKIPPED, FAILED = "executed", "skipped", "failed"


@dataclass
class ExecutionResult:
    status: str  # executed | skipped | failed
    started_at: datetime
    target: Optional[str]
    detail: str
    command: Optional[str] = None
    returncode: Optional[int] = None
    output: str = ""
    notes: List[str] = field(default_factory=list)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _render(text: str, execute: Execute) -> str:
    return text.replace("{target}", execute.target or "").replace("{ssh}", execute.ssh or "")


def _wrap_ssh(command: str, ssh: Optional[str]) -> List[str]:
    if ssh:
        return ["ssh", ssh, command]
    return ["/bin/sh", "-c", command]


def atomic_command(execute: Execute, technique: str) -> str:
    """The Invoke-AtomicTest invocation this case would run (also shown in dry-run)."""
    parts = [f"Invoke-AtomicTest {technique.split('.')[0]}"]
    if execute.atomic_guid:
        parts.append(f"-TestGuids {execute.atomic_guid}")
    elif execute.atomic_test:
        parts.append(f"-TestNames {shlex.quote(execute.atomic_test)}")
    if execute.input_args:
        pairs = "; ".join(f'{k}="{v}"' for k, v in execute.input_args.items())
        parts.append(f"-InputArgs @{{{pairs}}}")
    return " ".join(parts)


def _powershell(inner: str) -> str:
    escaped = inner.replace('"', '\\"')
    return f'pwsh -NoProfile -Command "{escaped}"'


def _run(command: str, ssh: Optional[str], started: datetime, target: Optional[str], timeout: float) -> ExecutionResult:
    argv = _wrap_ssh(command, ssh)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603
    except FileNotFoundError as exc:
        return ExecutionResult(FAILED, started, target, f"could not launch: {exc}", command=command)
    except subprocess.TimeoutExpired:
        return ExecutionResult(FAILED, started, target, f"timed out after {timeout}s", command=command)
    output = (proc.stdout + proc.stderr).strip()
    status = EXECUTED if proc.returncode == 0 else FAILED
    detail = "executed" if status == EXECUTED else f"exited {proc.returncode}"
    return ExecutionResult(status, started, target, detail, command=command, returncode=proc.returncode, output=output)


def execute_case(
    case: Case,
    allow_execution: bool = False,
    confirm: Optional[Callable[[str], bool]] = None,
    timeout: float = 300.0,
) -> ExecutionResult:
    ex = case.execute
    started = _now()
    target = ex.target or (ex.ssh.split("@")[-1] if ex.ssh else None)

    if ex.executor == "dryrun":
        planned = _planned_command(case)
        note = f"dry run; would execute: {planned}" if planned else "dry run; nothing to execute"
        return ExecutionResult(SKIPPED, started, target, note, command=planned)

    if ex.executor == "manual":
        steps = _planned_command(case) or "(see the case description)"
        if confirm is None:
            return ExecutionResult(
                SKIPPED, started, target, "manual case not confirmed (use --assume-executed or the interactive prompt)"
            )
        prompt = f"Run this on {target or 'the target'} now, then confirm:\n    {steps}\nExecuted? [y/N] "
        if confirm(prompt):
            return ExecutionResult(EXECUTED, _now(), target, "operator confirmed manual execution", command=steps)
        return ExecutionResult(SKIPPED, started, target, "operator did not confirm manual execution", command=steps)

    # command / atomic: real execution, gated twice.
    planned = _planned_command(case)
    if not case.authorized:
        return ExecutionResult(
            SKIPPED, started, target, "case is not marked authorized: true; skipping execution", command=planned
        )
    if not allow_execution:
        return ExecutionResult(
            SKIPPED, started, target, "execution not enabled (pass --allow-execution)", command=planned
        )
    result = _run(planned, ex.ssh, started, target, timeout)
    if ex.cleanup and result.status == EXECUTED:
        cleanup = _run(_render(ex.cleanup, ex), ex.ssh, _now(), target, timeout)
        result.notes.append("cleanup ran" if cleanup.status == EXECUTED else f"cleanup failed: {cleanup.detail}")
    return result


def _planned_command(case: Case) -> Optional[str]:
    ex = case.execute
    if ex.executor == "command":
        return _render(ex.command, ex) if ex.command else None
    if ex.command and ex.executor == "manual" and not (ex.atomic_guid or ex.atomic_test):
        return _render(ex.command, ex)
    if ex.atomic_guid or ex.atomic_test:
        return _powershell(atomic_command(ex, case.technique))
    return None
