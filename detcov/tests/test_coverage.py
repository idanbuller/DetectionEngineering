from detcov.catalog import Detection
from detcov.coverage import (
    AT_RISK,
    BROKEN,
    COVERED,
    NO_DATA,
    PROVEN,
    UNKNOWN_DATA,
    build,
    load_detval_results,
    summary,
)
from detcov.health import Health, SourceHealth

NOW = 1_000_000.0


def health(*facts):
    return Health([SourceHealth(*f) for f in facts], freshness_seconds=3600, now=NOW)


def det(tech, indexes=None, sourcetypes=None, macro=False):
    d = Detection("p.yml", tech + " rule", [tech], "index=x", set(indexes or []), set(sourcetypes or []), macro)
    return d


def tiers(coverage):
    return {c.technique: c.tier for c in coverage}


def test_proven_covered_and_atrisk_and_nodata():
    h = health(("edr", "p", NOW, 5), ("proxy", "web", NOW - 99999, 5))
    dets = [
        det("T1059.001", ["edr"], ["p"]),  # healthy + validated pass -> proven
        det("T1110.001", ["edr"], ["p"]),  # healthy, no validation -> covered
        det("T1071.001", ["proxy"], ["web"]),  # stale -> at_risk
        det("T1003.001", ["lsass"], ["x"]),  # missing -> no_data
    ]
    cov = build(dets, h, {"T1059.001": "pass"})
    assert tiers(cov) == {
        "T1059.001": PROVEN,
        "T1110.001": COVERED,
        "T1071.001": AT_RISK,
        "T1003.001": NO_DATA,
    }


def test_broken_beats_everything():
    h = health(("edr", "p", NOW, 5))
    cov = build([det("T1059.001", ["edr"], ["p"])], h, {"T1059.001": "fail"})
    assert cov[0].tier == BROKEN


def test_macro_index_is_unknown():
    cov = build([det("T1486", macro=True)], health(("edr", "p", NOW, 5)))
    assert cov[0].tier == UNKNOWN_DATA and "macro" in cov[0].reason


def test_no_health_information_is_unknown():
    from detcov.health import empty

    cov = build([det("T1059.001", ["edr"], ["p"])], empty())
    assert cov[0].tier == UNKNOWN_DATA


def test_validated_technique_with_no_rule_still_appears():
    cov = build([], health(), {"T1566.001": "pass"})
    assert cov[0].technique == "T1566.001" and cov[0].rule_count == 0


def test_multiple_rules_use_worst_data():
    h = health(("edr", "p", NOW, 5), ("proxy", "web", NOW - 99999, 5))
    dets = [det("T1071.001", ["edr"], ["p"]), det("T1071.001", ["proxy"], ["web"])]
    cov = build(dets, h)
    assert cov[0].rule_count == 2 and cov[0].tier == AT_RISK


def test_load_detval_results_prefers_pass(tmp_path):
    import json

    p = tmp_path / "d.json"
    p.write_text(
        json.dumps(
            [
                {"technique": "T1059.001", "status": "fail"},
                {"technique": "T1059.001", "status": "pass"},
                {"technique": "T1110", "status": "blocked"},
            ]
        )
    )
    res = load_detval_results(str(p))
    assert res == {"T1059.001": "pass"}  # blocked is ignored


def test_summary_counts():
    h = health(("edr", "p", NOW, 5))
    cov = build([det("T1059.001", ["edr"], ["p"]), det("T1110.001", ["edr"], ["p"])], h, {"T1059.001": "pass"})
    s = summary(cov)
    assert s[PROVEN] == 1 and s[COVERED] == 1
