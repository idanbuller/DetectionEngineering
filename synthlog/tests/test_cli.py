import json
import os
from pathlib import Path

import pytest

from synthlog.cli import main

EXAMPLE = str(Path(__file__).resolve().parents[1] / "examples" / "corp.yml")


def test_validate_example(capsys):
    assert main(["validate", EXAMPLE]) == 0
    out = capsys.readouterr().out
    assert "ok" in out and "scenario ssh_bruteforce_then_discovery: 1 instance(s) [malicious]" in out


def test_generate_example(tmp_path, capsys):
    assert main(["generate", EXAMPLE, "-o", str(tmp_path), "--duration", "2h"]) == 0
    assert sorted(os.listdir(tmp_path)) == ["edr_process.jsonl", "linux_auth.log", "truth.json"]
    truth = json.loads((tmp_path / "truth.json").read_text())
    assert {t["scenario"] for t in truth} == {
        "ssh_bruteforce_then_discovery",
        "office_encoded_powershell",
        "admin_password_typos",
    }


def test_spl_limit_and_filter(capsys):
    assert main(["spl", EXAMPLE]) == 2
    assert "too many" in capsys.readouterr().err
    assert main(["spl", EXAMPLE, "--no-background", "--source", "linux_auth"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("| makeresults format=json") and "edr" not in out
    assert main(["spl", EXAMPLE, "--no-background", "--source", "nope"]) == 2


def test_preview(capsys):
    assert main(["preview", EXAMPLE, "-n", "1", "--duration", "1h"]) == 0
    out = capsys.readouterr().out
    assert "== linux_auth" in out and "scenario" in out


def test_errors_are_reported_cleanly(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("sources:\n  s:\n    fields:\n      a: {int: [9, 1]}\n")
    assert main(["validate", str(bad)]) == 2
    assert "sources.s.fields.a.int" in capsys.readouterr().err


def test_hec_needs_token(monkeypatch, capsys):
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    assert main(["hec", EXAMPLE, "--url", "http://localhost:1"]) == 2
    assert "SPLUNK_HEC_TOKEN" in capsys.readouterr().err


def test_infer_cli(tmp_path, capsys):
    samples = tmp_path / "s.jsonl"
    samples.write_text('{"time": 1767571200, "action": "a"}\n{"time": 1767571260, "action": "a"}\n')
    out = tmp_path / "spec.yml"
    assert main(["infer", str(samples), "--name", "app", "-o", str(out)]) == 0
    assert main(["validate", str(out)]) == 0


@pytest.mark.parametrize("args", [["generate"], ["nope"]])
def test_usage_errors(args):
    with pytest.raises(SystemExit):
        main(args)
