import pytest

from detval.casespec import CaseError, discover, load_case, parse_duration


def write(tmp_path, body, name="t.case.yml"):
    p = tmp_path / name
    p.write_text(body)
    return str(p)


def test_parse_duration():
    assert parse_duration("15m", "d").total_seconds() == 900
    assert parse_duration("1h30m", "d").total_seconds() == 5400
    assert parse_duration(45, "d").total_seconds() == 45
    with pytest.raises(CaseError, match="invalid duration"):
        parse_duration("soon", "d")


def test_load_full_case(tmp_path):
    case = load_case(
        write(
            tmp_path,
            """
technique: T1059.001
name: Encoded PowerShell
tactic: execution
authorized: true
execute:
  executor: atomic
  atomic_guid: abc-123
  target: canary-01
  input_args: {command_to_encode: "calc.exe"}
expect:
  - name: edr sees it
    kind: telemetry
    search: index=edr powershell
    match: {dest: "{target}"}
    settle: 30s
    window: 10m
  - kind: notable
    search: index=notable T1059
""",
        )
    )
    assert case.technique == "T1059.001" and case.authorized
    assert case.execute.executor == "atomic" and case.execute.atomic_guid == "abc-123"
    assert case.execute.input_args == {"command_to_encode": "calc.exe"}
    assert len(case.expect) == 2
    assert case.expect[0].window.total_seconds() == 600
    assert case.expect[1].name == "notable check 2" and case.expect[1].kind == "notable"


def test_defaults_and_discovery(tmp_path):
    (tmp_path / "sub").mkdir()
    write(
        tmp_path / "sub", "technique: T1003\nexecute: {executor: dryrun}\nexpect: [{search: index=x}]\n", "a.case.yml"
    )
    (tmp_path / "not_a_case.yml").write_text("technique: T1")
    found = discover([str(tmp_path)])
    assert len(found) == 1 and found[0].endswith("a.case.yml")
    case = load_case(found[0])
    assert case.authorized is False and case.execute.executor == "dryrun"
    assert case.expect[0].window.total_seconds() == 900  # default 15m


@pytest.mark.parametrize(
    "body, message",
    [
        ("execute: {}\nexpect: [{search: x}]\n", "needs a technique"),
        ("technique: T1\nexpect: []\n", "at least one SIEM check"),
        ("technique: T1\nexpect: [{search: x}]\nauthorized: yes-please\n", "true or false"),
        ("technique: T1\nexecute: {executor: nope}\nexpect: [{search: x}]\n", "executor must be one of"),
        ("technique: T1\nexecute: {executor: command}\nexpect: [{search: x}]\n", "needs a command"),
        ("technique: T1\nexecute: {executor: atomic}\nexpect: [{search: x}]\n", "needs atomic_guid"),
        ("technique: T1\nexpect: [{kind: alarm, search: x}]\n", "kind must be one of"),
        ("technique: T1\nexpect: [{search: x, min_rows: 0}]\n", "min_rows must be a positive"),
        ("technique: T1\nexpect: [{}]\n", "needs a search"),
        ("technique: T1\ncolour: red\nexpect: [{search: x}]\n", "unknown key"),
    ],
)
def test_errors(tmp_path, body, message):
    with pytest.raises(CaseError, match=message):
        load_case(write(tmp_path, body))
