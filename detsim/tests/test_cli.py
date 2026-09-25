import json
from pathlib import Path

from detsim.cli import main, simulate_detection

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "detections" / "library"


def write(tmp_path, body, name="d.yml"):
    p = tmp_path / name
    p.write_text(body)
    return str(p)


def test_simulate_a_detection_auto(tmp_path):
    path = write(
        tmp_path,
        "name: T\nmitre: [T1059.002]\nsearch: |\n"
        '  index=edr sourcetype="edr:process" (process="*/nscurl" AND cmdline="*--download *")\n',
    )
    [sim] = simulate_detection(path)
    assert sim.status == "auto" and sim.techniques == ["T1059.002"]
    assert sim.event["process"].endswith("/nscurl") and "--download " in sim.event["cmdline"]
    assert sim.verification.startswith("| makeresults format=json") and "| search" in sim.verification
    assert "redcanaryco/atomic-red-team" in sim.guide and "T1059.002" in sim.guide


def test_manual_when_unsatisfiable(tmp_path):
    path = write(tmp_path, 'name: C\nsearch: \'x="alpha" x="beta"\'\n')
    [sim] = simulate_detection(path)
    assert sim.status == "manual" and sim.reason
    assert "Manual simulation required" in sim.guide


def test_cli_text_and_json_over_catalog(capsys):
    assert main(["simulate", str(CATALOG)]) == 0
    out = capsys.readouterr().out
    assert "auto-simulatable" in out and "hit " in out

    assert main(["simulate", str(CATALOG), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) >= 15
    assert all(d["status"] in ("auto", "manual") for d in data)
    auto = [d for d in data if d["status"] == "auto"]
    assert auto and all(d["event"] and d["verification"] for d in auto)


def test_cli_writes_guides(tmp_path, capsys):
    assert main(["simulate", str(CATALOG / "binary_padding_macos.yml"), "-o", str(tmp_path)]) == 0
    assert (tmp_path / "SIMULATE.md").exists()
    guides = list(tmp_path.glob("*.guide.md"))
    spls = list(tmp_path.glob("*.spl"))
    assert guides and spls
    assert "Synthetic hit" in guides[0].read_text()


def test_fail_on_manual(tmp_path):
    write(tmp_path, 'name: C\nsearch: \'x="a" x="b"\'\n', "conflict.yml")
    assert main(["simulate", str(tmp_path)]) == 0
    assert main(["simulate", str(tmp_path), "--fail-on-manual"]) == 1
