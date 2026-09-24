from detval.casespec import Execute, load_case
from detval.executors import EXECUTED, FAILED, SKIPPED, atomic_command, execute_case


def case(tmp_path, body):
    p = tmp_path / "c.case.yml"
    p.write_text(body)
    return load_case(str(p))


ATOMIC = """
technique: T1059.001
authorized: {auth}
execute:
  executor: atomic
  atomic_guid: 3c73d728
  target: canary-01
  input_args: {{command_to_encode: calc.exe}}
expect: [{{search: index=edr}}]
"""


def test_atomic_command_uses_parent_technique_and_args():
    ex = Execute("atomic", "guid-1", None, None, {"a": "b", "c": "d"}, "t", None, None)
    cmd = atomic_command(ex, "T1059.001")
    assert cmd == 'Invoke-AtomicTest T1059 -TestGuids guid-1 -InputArgs @{a="b"; c="d"}'


def test_atomic_plan_is_shown_even_when_skipped(tmp_path):
    c = case(tmp_path, ATOMIC.format(auth="false"))
    r = execute_case(c, allow_execution=True)
    assert r.status == SKIPPED
    assert r.command and "Invoke-AtomicTest T1059 -TestGuids 3c73d728" in r.command


def test_atomic_requires_authorized_and_allow(tmp_path):
    unauth = case(tmp_path, ATOMIC.format(auth="false"))
    r = execute_case(unauth, allow_execution=True)
    assert r.status == SKIPPED and "not marked authorized" in r.detail

    auth = case(tmp_path, ATOMIC.format(auth="true"))
    r = execute_case(auth, allow_execution=False)
    assert r.status == SKIPPED and "execution not enabled" in r.detail


def test_command_runs_only_when_authorized_and_allowed(tmp_path):
    body = (
        "technique: T1110\nauthorized: true\n"
        "execute: {executor: command, command: 'echo ran', target: c1}\nexpect: [{search: x}]\n"
    )
    c = case(tmp_path, body)
    blocked = execute_case(c, allow_execution=False)
    assert blocked.status == SKIPPED and blocked.command == "echo ran"
    ran = execute_case(c, allow_execution=True)
    assert ran.status == EXECUTED and ran.returncode == 0 and "ran" in ran.output


def test_command_failure_is_reported(tmp_path):
    body = "technique: T1\nauthorized: true\nexecute: {executor: command, command: 'exit 3'}\nexpect: [{search: x}]\n"
    r = execute_case(case(tmp_path, body), allow_execution=True)
    assert r.status == FAILED and r.returncode == 3


def test_command_target_substitution(tmp_path):
    body = (
        "technique: T1\nauthorized: true\n"
        "execute: {executor: command, command: 'echo {target}', target: host9}\nexpect: [{search: x}]\n"
    )
    r = execute_case(case(tmp_path, body), allow_execution=True)
    assert r.output.strip() == "host9"


def test_manual_confirmation(tmp_path):
    body = "technique: T1\nexecute: {executor: manual, command: 'do the thing', target: c1}\nexpect: [{search: x}]\n"
    c = case(tmp_path, body)
    assert execute_case(c).status == SKIPPED  # no confirm callback
    assert execute_case(c, confirm=lambda p: True).status == EXECUTED
    assert execute_case(c, confirm=lambda p: False).status == SKIPPED


def test_dryrun_executor_shows_plan(tmp_path):
    body = "technique: T1059\nexecute: {executor: dryrun, atomic_guid: g1}\nexpect: [{search: x}]\n"
    r = execute_case(case(tmp_path, body))
    assert r.status == SKIPPED and "would execute" in r.detail and "Invoke-AtomicTest T1059" in r.command
