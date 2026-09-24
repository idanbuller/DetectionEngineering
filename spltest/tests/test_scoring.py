import textwrap

import pytest
import yaml
from synthlog.engine import generate
from synthlog.spec import parse_spec

from spltest.scoring import row_matches, score
from spltest.testspec import DetectionTest, Expectation

DATASET = """
seed: 5
start: 2026-01-05T00:00:00Z
duration: 24h
entities:
  user: {count: 5, fields: {name: "{first}.{last}", team: {choice: [it, eng]}}}
sources:
  auth:
    events: 0
    fields: {user: {entity: user.name}, src: {ipv4: 10.0.0.0/24}}
scenarios:
  - id: attack
    at: 1h
    repeat: 2
    every: 1h
    bind: {user: {pick: 0}, attacker: {values: {ip: {ipv4: 203.0.113.0/24}}}}
    steps: [{count: 3, set: {src: "{attacker.ip}"}}]
  - id: lookalike
    label: benign
    at: 5h
    bind: {user: {pick: 1}}
    steps: [{count: 2}]
"""


@pytest.fixture(scope="module")
def truth():
    return generate(parse_spec(yaml.safe_load(textwrap.dedent(DATASET))), include_background=False).truth


def make_test(*expect, max_unexpected=None):
    return DetectionTest("t.test.yml", "t", "index=x", None, "d.yml", False, None, {}, max_unexpected, list(expect))


def ip(truth, scenario, n=0):
    return [t for t in truth if t["scenario"] == scenario][n]["entities"]["attacker"]["ip"]


def test_row_matching(truth):
    run = truth[0]
    row = {"src": run["entities"]["attacker"]["ip"], "user": ["x", run["entities"]["user"]["name"]]}
    assert row_matches(row, run, {"src": "{attacker.ip}", "user": "{user.name}"})
    assert not row_matches({"src": "1.2.3.4"}, run, {"src": "{attacker.ip}"})
    assert row_matches(row, run, {})  # default: any entity value appears in the row
    assert not row_matches({"count": "3"}, run, {})


def test_time_parsing_and_windows(truth):
    from spltest.scoring import parse_time, row_in_window

    assert parse_time("1767571200") == 1767571200.0
    assert parse_time("2026-01-05 00:00:00.000 UTC") == 1767571200.0
    assert parse_time("2026-01-05T00:00:00Z") == 1767571200.0
    assert parse_time(["x", "1767571200"]) == 1767571200.0
    assert parse_time("42") is None and parse_time("soon") is None
    run = truth[0]
    assert row_in_window({"user": "x"}, run)  # no time fields: entity match decides
    assert row_in_window({"_time": _epoch(run["start"])}, run)
    assert not row_in_window({"_time": "1767571200"}, run)  # hours before the run


def test_detected_and_quiet(truth):
    test = make_test(Expectation("attack", None, {"src": "{attacker.ip}"}), Expectation("lookalike", None, {}))
    rows = [{"src": ip(truth, "attack", 0)}, {"src": ip(truth, "attack", 1)}]
    result = score(test, truth, rows)
    assert result.passed
    attack, lookalike = result.expectations
    assert attack.fires and attack.detected == 2 and len(attack.instances) == 2
    assert not lookalike.fires and lookalike.detected == 0


def _epoch(iso):
    from datetime import datetime

    return str(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def test_missed_run(truth):
    # Both runs bind the same attacker, so only the row's time can tell them apart.
    first = [t for t in truth if t["scenario"] == "attack"][0]
    test = make_test(Expectation("attack", None, {"src": "{attacker.ip}"}))
    rows = [{"src": ip(truth, "attack", 0), "firstTime": _epoch(first["start"]), "lastTime": _epoch(first["end"])}]
    assert not score(test, truth, rows).passed
    any_test = make_test(Expectation("attack", None, {"src": "{attacker.ip}"}, instances="any"))
    assert score(any_test, truth, rows).passed


def test_false_positive_on_benign(truth):
    lookalike_user = [t for t in truth if t["scenario"] == "lookalike"][0]["entities"]["user"]["name"]
    test = make_test(Expectation("lookalike", None, {"user": "{user.name}"}))
    result = score(test, truth, [{"user": lookalike_user}])
    assert not result.passed and result.expectations[0].detected == 1


def test_explicit_fires_overrides_label(truth):
    test = make_test(Expectation("lookalike", True, {}))
    lookalike_user = [t for t in truth if t["scenario"] == "lookalike"][0]["entities"]["user"]["name"]
    assert score(test, truth, [{"user": lookalike_user}]).passed


def test_unexpected_rows(truth):
    test = make_test(Expectation("attack", None, {"src": "{attacker.ip}"}, instances="any"), max_unexpected=0)
    rows = [{"src": ip(truth, "attack")}, {"src": "192.0.2.99"}]
    result = score(test, truth, rows)
    assert len(result.unexpected_rows) == 1 and not result.passed
    test.max_unexpected = None
    assert score(test, truth, rows).passed


def test_errors_are_explained(truth):
    with pytest.raises(ValueError, match="not in the dataset"):
        score(make_test(Expectation("nope", None, {})), truth, [])
    with pytest.raises(ValueError, match=r"uses \{victim.ip\}.*available: user.name"):
        score(make_test(Expectation("attack", None, {"src": "{victim.ip}"})), truth, [])
