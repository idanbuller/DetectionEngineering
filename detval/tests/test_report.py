import io
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from detval.casespec import Case, Check, Execute
from detval.executors import EXECUTED, SKIPPED, ExecutionResult
from detval.report import navigator_layer, report_json, report_text, write_junit
from detval.runner import CaseResult
from detval.verify import CheckResult


def check(name="c", kind="telemetry"):
    from datetime import timedelta

    return Check(name, kind, "index=x", 1, {}, timedelta(minutes=5), timedelta(0), timedelta(seconds=30))


def make_result(technique, status, detected):
    case = Case(
        "p.case.yml",
        technique,
        technique + " case",
        "execution",
        "",
        True,
        Execute("dryrun", None, None, None, {}, "c1", None, None),
        [check()],
    )
    now = datetime(2026, 1, 5, tzinfo=timezone.utc)
    ex_status = EXECUTED if status != "blocked" else SKIPPED
    execution = ExecutionResult(ex_status, now, "c1", "detail")
    checks = [CheckResult(check(), detected, 1 if detected else 0, 12.0 if detected else None, 1)]
    return CaseResult(case, execution, checks)


def test_status_logic():
    assert make_result("T1", "pass", True).status == "pass"
    assert make_result("T1", "fail", False).status == "fail"
    assert make_result("T1", "blocked", False).status == "blocked"


def test_text_report():
    out = io.StringIO()
    report_text([make_result("T1059", "pass", True), make_result("T1110", "fail", False)], out, verbose=True)
    text = out.getvalue()
    assert "PASS  T1059" in text and "FAIL  T1110" in text
    assert "in 12s" in text and "1 pass, 1 fail" in text


def test_json_report():
    out = io.StringIO()
    report_json([make_result("T1059", "pass", True)], out)
    data = json.loads(out.getvalue())
    assert data[0]["technique"] == "T1059" and data[0]["status"] == "pass"
    assert data[0]["checks"][0]["latency_seconds"] == 12.0


def test_junit(tmp_path):
    path = tmp_path / "j.xml"
    write_junit([make_result("T1059", "pass", True), make_result("T1110", "fail", False)], str(path))
    suite = ET.parse(path).getroot()
    assert suite.get("tests") == "2" and suite.get("failures") == "1"


def test_navigator_layer():
    results = [
        make_result("T1059", "pass", True),
        make_result("T1059", "fail", False),
        make_result("T1110", "pass", True),
    ]
    layer = navigator_layer(results)
    techs = {t["techniqueID"]: t for t in layer["techniques"]}
    assert layer["domain"] == "enterprise-attack"
    # T1059 has a pass and a fail -> worst status (fail) colors it
    assert techs["T1059"]["metadata"][0]["value"] == "fail"
    assert "1/2" in techs["T1059"]["comment"]
    assert techs["T1110"]["metadata"][0]["value"] == "pass"
