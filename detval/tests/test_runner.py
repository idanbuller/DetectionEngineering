from detval.casespec import load_case
from detval.runner import run_case


def make_case(tmp_path, body):
    p = tmp_path / "c.case.yml"
    p.write_text(body)
    return load_case(str(p))


DRYRUN = """
technique: T1059.001
name: Encoded PowerShell
execute: {executor: dryrun, atomic_guid: g1, target: canary-01}
expect:
  - {name: edr, kind: telemetry, search: index=edr, match: {dest: "{target}"}, settle: 0s, window: 5m, poll: 1m}
  - {name: notable, kind: notable, search: index=notable, settle: 0s, window: 5m, poll: 1m}
"""


def test_pass_when_all_signals_appear(tmp_path, clock, make_search):
    rows = [{"_time": str(int(clock.now().timestamp())), "dest": "canary-01"}]
    search = make_search(rows_by_marker={"edr": rows, "notable": rows})
    r = run_case(make_case(tmp_path, DRYRUN), search, now=clock.now, sleep=clock.sleep)
    assert r.status == "pass" and r.detected
    assert [c.detected for c in r.checks] == [True, True]


def test_fail_when_a_signal_is_missing(tmp_path, clock, make_search):
    rows = [{"_time": str(int(clock.now().timestamp())), "dest": "canary-01"}]
    search = make_search(rows_by_marker={"edr": rows})  # notable never appears
    r = run_case(make_case(tmp_path, DRYRUN), search, now=clock.now, sleep=clock.sleep)
    assert r.status == "fail" and not r.detected
    assert [c.detected for c in r.checks] == [True, False]


def test_blocked_when_execution_needed_but_skipped(tmp_path, clock, make_search):
    body = """
technique: T1110
authorized: false
execute: {executor: command, command: "echo x", target: c1}
expect: [{search: index=notable, settle: 0s, window: 1m, poll: 30s}]
"""
    # not authorized + no signal -> blocked, not a hard fail
    r = run_case(make_case(tmp_path, body), make_search(), allow_execution=True, now=clock.now, sleep=clock.sleep)
    assert r.status == "blocked" and r.execution.status == "skipped"


def test_error_when_execution_fails(tmp_path, clock, make_search):
    body = """
technique: T1
authorized: true
execute: {executor: command, command: "exit 5"}
expect: [{search: index=notable, settle: 0s, window: 1m}]
"""
    r = run_case(make_case(tmp_path, body), make_search(), allow_execution=True, now=clock.now, sleep=clock.sleep)
    assert r.status == "error" and r.checks == []


def test_verify_only_never_executes(tmp_path, clock, make_search):
    body = """
technique: T1
authorized: true
execute: {executor: command, command: "echo SHOULD-NOT-RUN", target: c1}
expect: [{search: index=notable, settle: 0s, window: 1m, poll: 30s}]
"""
    r = run_case(make_case(tmp_path, body), make_search(), allow_execution=False, now=clock.now, sleep=clock.sleep)
    assert r.execution.status == "skipped"
