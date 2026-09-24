import json
from pathlib import Path

from detval.cli import main

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "examples" / "cases"


def test_list(capsys):
    assert main(["list", str(CASES)]) == 0
    out = capsys.readouterr().out
    assert "T1059.001" in out and "atomic" in out and "not authorized" in out
    assert "Invoke-AtomicTest T1059" in out


# A tiny case so verify's real poll loop finishes in a couple of seconds.
FAST_CASE = """
technique: T1110
authorized: true
execute: {executor: command, command: "echo SHOULD-NOT-RUN", target: c1}
expect: [{search: index=notable, settle: 0s, window: 2s, poll: 1s}]
"""


def test_verify_never_executes_and_reports(capsys, monkeypatch, tmp_path):
    from detval import cli

    monkeypatch.setattr(cli, "_client", lambda args: type("C", (), {"search": staticmethod(lambda *a: [])})())
    case = tmp_path / "fast.case.yml"
    case.write_text(FAST_CASE)
    rc = main(["verify", str(case), "--splunk-url", "http://x", "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["execution"]["status"] == "skipped"  # verify never executes the command
    assert data[0]["status"] == "blocked" and rc == 0  # skipped execution + no signal = blocked, exit 0


def test_run_needs_url(capsys, monkeypatch):
    monkeypatch.delenv("SPLUNK_URL", raising=False)
    assert main(["run", str(CASES)]) == 2
    assert "--splunk-url" in capsys.readouterr().err


def test_layer_from_json(tmp_path, capsys):
    results = [{"technique": "T1059", "status": "pass"}, {"technique": "T1059", "status": "fail"}]
    f = tmp_path / "r.json"
    f.write_text(json.dumps(results))
    assert main(["layer", str(f)]) == 0
    layer = json.loads(capsys.readouterr().out)
    assert layer["techniques"][0]["techniqueID"] == "T1059"
    assert layer["techniques"][0]["metadata"][0]["value"] == "fail"


def test_no_cases_found(tmp_path, capsys):
    assert main(["list", str(tmp_path)]) == 2
    assert "no *.case.yml" in capsys.readouterr().err
