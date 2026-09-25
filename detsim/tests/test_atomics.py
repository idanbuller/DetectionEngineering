import pytest

from detsim.atomics import literals, load_index, match
from detsim.predicate import from_spl


def make_art(tmp_path, technique, tests):
    d = tmp_path / "atomics" / technique
    d.mkdir(parents=True)
    body = {"atomic_tests": tests}
    import yaml

    (d / f"{technique}.yaml").write_text(yaml.safe_dump(body))
    return str(tmp_path)


def test_load_index_and_command(tmp_path):
    art = make_art(
        tmp_path,
        "T1105",
        [
            {
                "name": "Curl Download File",
                "auto_generated_guid": "aaa",
                "supported_platforms": ["windows"],
                "executor": {"command": "curl -o out http://x"},
            },
            {
                "name": "File download via nscurl",
                "auto_generated_guid": "bbb",
                "supported_platforms": ["macos"],
                "executor": {"command": "nscurl --download http://x --output out"},
            },
            {"name": "no guid", "executor": {"command": "x"}},  # skipped
        ],
    )
    index = load_index(art)
    assert len(index["T1105"]) == 2
    assert index["T1105"][0].command() == "Invoke-AtomicTest T1105 -TestGuids aaa"


def test_literals_skips_meta_and_negation():
    ast = from_spl('index=edr sourcetype="edr:process" process="*/nscurl" cmdline="*--download *" NOT user="svc"').ast
    lits = literals(ast)
    assert "nscurl" in lits and "download" in lits
    assert "edr" not in lits and "svc" not in lits  # index/sourcetype and NOT excluded


def test_match_prefers_name_and_specific_test(tmp_path):
    art = make_art(
        tmp_path,
        "T1105",
        [
            {
                "name": "Curl Download File",
                "auto_generated_guid": "aaa",
                "supported_platforms": ["windows"],
                "executor": {"command": "curl --output out http://x"},
            },
            {
                "name": "File download via nscurl",
                "auto_generated_guid": "bbb",
                "supported_platforms": ["macos"],
                "executor": {"command": "nscurl --download http://x"},
            },
        ],
    )
    index = load_index(art)
    lits = literals(from_spl('process="*/nscurl" cmdline="*--download *"').ast)
    ranked = match(["T1105"], lits, index)
    assert ranked[0].test.guid == "bbb" and ranked[0].score > ranked[1].score  # nscurl test wins on name


def test_match_technique_only_when_no_literal_overlap(tmp_path):
    art = make_art(
        tmp_path,
        "T1123",
        [
            {
                "name": "Record via ffmpeg",
                "auto_generated_guid": "ccc",
                "supported_platforms": ["linux"],
                "executor": {"command": "ffmpeg -f alsa"},
            },
        ],
    )
    index = load_index(art)
    ranked = match(["T1123"], ["nonexistent"], index)
    assert len(ranked) == 1 and ranked[0].score == 0  # still surfaced, technique-only


def test_missing_atomics_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_index(str(tmp_path))
