import pytest

from detsim.predicate import from_spl, matches
from detsim.synth import Unsatisfiable, synthesize


def synth(spl):
    return synthesize(from_spl(spl))


def check(spl):
    """Synthesize and assert the event actually satisfies the detection."""
    p = from_spl(spl)
    s = synthesize(p)
    assert matches(p.ast, s.event), (spl, s.event)
    return s.event


def test_equality_and_wildcards():
    e = check('index=edr sourcetype="edr:process" process="*/nscurl" cmdline="*--download *"')
    assert e["index"] == "edr" and e["sourcetype"] == "edr:process"
    assert e["process"].endswith("/nscurl") and "--download " in e["cmdline"]


def test_startswith_endswith_contains_merge():
    e = check('file="*/Library/LaunchAgents/*" file2="*.plist"')  # separate fields
    assert "/Library/LaunchAgents/" in e["file"] and e["file2"].endswith(".plist")
    e2 = check('path="*/Library/LaunchAgents/*" path="*.plist"')  # same field, merged
    assert "/Library/LaunchAgents/" in e2["path"] and e2["path"].endswith(".plist")


def test_or_picks_a_branch():
    e = check('(process="*/sh" OR process="*/bash") cmdline="*curl*"')
    assert e["process"].endswith("/sh") or e["process"].endswith("/bash")
    assert "curl" in e["cmdline"]


def test_numeric():
    e = check("index=x count>10")
    assert int(e["count"]) > 10


def test_not_is_left_unset():
    e = check('index=edr a="1" NOT evil="true"')
    assert "evil" not in e  # excluded field stays absent so the NOT holds


def test_keyword_goes_to_raw():
    e = check('index=os "Failed password"')
    assert "Failed password" in e["_raw"]


def test_unsatisfiable_conflict():
    with pytest.raises(Unsatisfiable):
        synth('x="alpha" x="beta"')  # two different exact values for one field
