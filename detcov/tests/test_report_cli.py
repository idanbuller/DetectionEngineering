import json
from pathlib import Path

from detcov.catalog import Detection
from detcov.cli import main
from detcov.coverage import build
from detcov.health import Health, SourceHealth
from detcov.report import navigator_layer, report_text

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
NOW = 1_000_000.0


def sample():
    h = Health([SourceHealth("edr", "p", NOW, 5), SourceHealth("proxy", "web", NOW - 99999, 5)], 3600, NOW)
    dets = [
        Detection("a.yml", "a", ["T1059.001"], "s", {"edr"}, {"p"}),
        Detection("b.yml", "b", ["T1071.001"], "s", {"proxy"}, {"web"}),
    ]
    return build(dets, h, {"T1059.001": "pass"})


def test_navigator_layer_shape():
    layer = navigator_layer(sample(), name="test")
    assert layer["domain"] == "enterprise-attack" and layer["name"] == "test"
    techs = {t["techniqueID"]: t for t in layer["techniques"]}
    assert techs["T1059.001"]["color"] != techs["T1071.001"]["color"]
    assert techs["T1059.001"]["metadata"][0]["value"] == "proven"


def test_text_report_highlights_silent_rules(capsys):
    import sys

    report_text(sample(), sys.stdout, color=False, verbose=True)
    out = capsys.readouterr().out
    assert "Rules likely not firing" in out and "T1071.001" in out
    assert "proven" in out and "at risk" in out


def test_cli_report_json_and_layer(tmp_path, capsys):
    layer = tmp_path / "layer.json"
    rc = main(
        [
            "report",
            str(EXAMPLES / "detections"),
            "--health",
            str(EXAMPLES / "health.json"),
            "--detval",
            str(EXAMPLES / "detval-results.json"),
            "-f",
            "json",
            "--layer",
            str(layer),
        ]
    )
    assert rc == 0
    data = {d["technique"]: d for d in json.loads(capsys.readouterr().out)}
    assert data["T1059.001"]["tier"] == "proven"
    assert data["T1110.001"]["tier"] == "broken"
    assert data["T1071.001"]["tier"] == "at_risk"
    assert data["T1486"]["tier"] == "unknown"
    assert json.loads(layer.read_text())["techniques"]


def test_cli_fail_on(tmp_path, capsys):
    args = [
        "report",
        str(EXAMPLES / "detections"),
        "--health",
        str(EXAMPLES / "health.json"),
        "--detval",
        str(EXAMPLES / "detval-results.json"),
    ]
    assert main(args + ["--fail-on", "broken"]) == 1  # a broken rule exists
    assert main(args + ["--fail-on", "at_risk"]) == 1  # at_risk too
    assert main(args + ["--fail-on", "none"]) == 0


def test_cli_layer_from_json(tmp_path, capsys):
    report = [{"technique": "T1059.001", "tier": "proven", "reason": "x"}]
    f = tmp_path / "r.json"
    f.write_text(json.dumps(report))
    assert main(["layer", str(f)]) == 0
    assert json.loads(capsys.readouterr().out)["techniques"][0]["techniqueID"] == "T1059.001"


def test_cli_no_detections(tmp_path, capsys):
    assert main(["report", str(tmp_path)]) == 2
    assert "no detections" in capsys.readouterr().err
