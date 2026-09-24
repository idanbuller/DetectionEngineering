import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from spltest import runner
from spltest.cli import main
from spltest.testspec import SpecFileError, load_test

from .test_splunk import FakeSplunk, splunk  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "tests"
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.mark.parametrize(
    "name, code",
    [("ssh_bruteforce", 0), ("office_spawns_powershell", 0), ("office_spawns_powershell_buggy", 1)],
)
def test_examples_score_against_recorded_splunk_results(name, code, capsys):
    rc = main(["score", str(EXAMPLES / f"{name}.test.yml"), "--results", str(FIXTURES / f"{name}.results.json")])
    out = capsys.readouterr().out
    assert rc == code
    if name.endswith("buggy"):
        assert "0/1 run(s) detected" in out and "spl-lint SPL104 (line 6)" in out


def test_compose_prints_the_search(capsys):
    assert main(["compose", str(EXAMPLES / "ssh_bruteforce.test.yml")]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("| makeresults format=json")
    assert '\n| search index=os sourcetype=linux_secure "Failed password"\n| rex' in captured.out
    assert "edr" not in captured.out  # sources: [linux_auth]
    assert "earliest=-24h" in captured.err


def test_run_against_splunk_with_junit(splunk, tmp_path, monkeypatch, capsys):  # noqa: F811
    FakeSplunk.rows = json.loads((FIXTURES / "ssh_bruteforce.results.json").read_text())
    monkeypatch.setenv("SPLUNK_TOKEN", "t")
    junit = tmp_path / "junit.xml"
    rc = main(["run", str(EXAMPLES / "ssh_bruteforce.test.yml"), "--splunk-url", splunk, "--junit", str(junit)])
    assert rc == 0
    sent = FakeSplunk.seen[0][2]["search"][0]
    assert sent.startswith("| makeresults format=json") and "| where count >= 8" in sent
    suite = ET.parse(junit).getroot()
    assert suite.get("tests") == "1" and suite.get("failures") == "0"


def test_run_reports_failures_in_junit_and_json(splunk, tmp_path, monkeypatch, capsys):  # noqa: F811
    FakeSplunk.rows = []
    monkeypatch.setenv("SPLUNK_TOKEN", "t")
    junit = tmp_path / "j.xml"
    rc = main(["run", str(EXAMPLES), "--splunk-url", splunk, "--junit", str(junit), "-f", "json"])
    assert rc == 1
    report = {r["name"]: r for r in json.loads(capsys.readouterr().out)}
    assert len(report) == 3 and not report["SSH brute force from a single source"]["passed"]
    suite = ET.parse(junit).getroot()
    assert suite.get("failures") == "3"


def test_run_needs_url(capsys, monkeypatch):
    monkeypatch.delenv("SPLUNK_URL", raising=False)
    assert main(["run", str(EXAMPLES), "--splunk-url", ""]) == 2
    assert "--splunk-url" in capsys.readouterr().err


def test_errors_become_failed_tests(tmp_path):
    t = tmp_path / "x.test.yml"
    t.write_text(
        f"search: '| tstats count where index=os'\ndataset: {ROOT / 'examples/datasets/small_corp.yml'}\n"
        "expect: [ssh_bruteforce]\n"
    )
    result = runner.run_test(load_test(str(t)), lambda s: [])
    assert not result.passed and "starts with | tstats" in result.error


def test_dataset_size_limit(tmp_path):
    t = tmp_path / "x.test.yml"
    t.write_text(
        f"search: index=os\ndataset: {ROOT / 'examples/datasets/small_corp.yml'}\nbackground: true\n"
        "expect: [ssh_bruteforce]\n"
    )
    with pytest.raises(ValueError, match="more than --max-events 100"):
        runner.prepare(load_test(str(t)), max_events=100)


@pytest.mark.parametrize(
    "body, message",
    [
        ("dataset: d.yml\nexpect: [a]\n", "exactly one of detection"),
        ("search: x\nexpect: [a]\n", "dataset"),
        ("search: x\ndataset: d.yml\n", "at least one scenario"),
        ("search: x\ndataset: d.yml\nexpect: [{scenario: a, fires: maybe}]\n", "true or false"),
        ("search: x\ndataset: d.yml\nexpect: [{scenario: a, colour: red}]\n", "unknown key"),
        ("search: x\ndataset: d.yml\ncolour: red\nexpect: [a]\n", "unknown key"),
        ("search: x\ndataset: d.yml\nmax_unexpected: -1\nexpect: [a]\n", "non-negative"),
    ],
)
def test_test_file_errors(tmp_path, body, message):
    t = tmp_path / "x.test.yml"
    t.write_text(body)
    with pytest.raises(SpecFileError, match=message):
        load_test(str(t))


def test_relative_paths_resolve_from_the_test_file():
    test = load_test(str(EXAMPLES / "ssh_bruteforce.test.yml"))
    assert os.path.isfile(test.dataset_path) and os.path.isfile(test.detection_path)
    assert test.name == "SSH brute force from a single source"
