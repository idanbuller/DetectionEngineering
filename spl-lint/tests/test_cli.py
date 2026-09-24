import io
import json
import sys

import pytest

from spl_lint.cli import main


@pytest.fixture
def run(capsys, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def _run(*args, stdin=None):
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        code = main(list(args))
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def test_clean_file_exits_zero(run, tmp_path):
    (tmp_path / "ok.spl").write_text("index=a | stats count by user")
    code, out, _ = run("ok.spl")
    assert code == 0 and "No issues" in out


def test_findings_exit_one_and_text_output(run, tmp_path):
    (tmp_path / "bad.spl").write_text('index=a | where user.name="x"')
    code, out, _ = run("bad.spl", "--color", "never")
    assert code == 1
    assert "bad.spl:1:17: SPL104 [error]" in out
    assert "^^^^^^^^^" in out


def test_info_findings_do_not_fail_by_default(run, tmp_path):
    (tmp_path / "info.spl").write_text("index=a action!=success")
    code, out, _ = run("info.spl")
    assert code == 0 and "SPL107" in out
    code, _, _ = run("info.spl", "--fail-on", "info")
    assert code == 1


def test_directory_walk_and_json(run, tmp_path):
    d = tmp_path / "detections"
    d.mkdir()
    (d / "a.yml").write_text("name: A\nsearch: sourcetype=x\n")
    (d / "notes.txt").write_text("index=* not spl")
    code, out, _ = run("detections", "-f", "json")
    data = json.loads(out)
    assert code == 1
    assert [(x["rule"], x["query_name"], x["line"]) for x in data] == [("SPL201", "A", 2)]


def test_sarif_output(run, tmp_path):
    (tmp_path / "q.spl").write_text("index=a | join x [search index=b]")
    code, out, _ = run("q.spl", "-f", "sarif")
    sarif = json.loads(out)
    run0 = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run0["tool"]["driver"]["rules"]} >= {"SPL204"}
    [result] = run0["results"]
    assert result["ruleId"] == "SPL204" and result["level"] == "warning"
    assert result["locations"][0]["physicalLocation"]["region"]["startColumn"] == 11


def test_github_output(run, tmp_path):
    (tmp_path / "q.spl").write_text("index=a | join x [search index=b]")
    _, out, _ = run("q.spl", "-f", "github")
    assert out.startswith("::warning file=q.spl,line=1,col=11,")
    assert "title=SPL204 join::" in out


def test_stdin(run):
    code, out, _ = run("-", stdin="index=a | transaction user")
    assert code == 1 and "SPL205" in out


def test_select_ignore_and_severity_config(run, tmp_path):
    (tmp_path / "q.spl").write_text("index=a | join x [search index=b] | STATS count")
    (tmp_path / ".spl-lint.yml").write_text("ignore: [join]\nselect: [SPL2, style]\nseverity:\n  SPL301: error\n")
    code, out, _ = run("q.spl", "-f", "json")
    assert [(x["rule"], x["severity"]) for x in json.loads(out)] == [("SPL301", "error")]
    assert code == 1


def test_bad_config_is_a_usage_error(run, tmp_path):
    (tmp_path / ".spl-lint.yml").write_text("unknown_option: 1\n")
    (tmp_path / "q.spl").write_text("index=a")
    code, _, err = run("q.spl")
    assert code == 2 and "unknown option" in err


def test_explain_and_list(run):
    code, out, _ = run("--explain", "SPL104")
    assert code == 0 and "concatenation" in out and "Bad:" in out
    code, out, _ = run("--explain", "join")
    assert code == 0 and out.startswith("SPL204 join")
    code, out, _ = run("--list-rules")
    assert code == 0 and "SPL000" in out and "SPL301" in out
    code, _, _ = run("--explain", "nope")
    assert code == 2


def test_unreadable_yaml_is_reported(run, tmp_path):
    (tmp_path / "broken.yml").write_text("search: [unclosed\n")
    code, _, err = run("broken.yml")
    assert code == 2 and "broken.yml" in err
