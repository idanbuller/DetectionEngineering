import pytest

from spltest.compose import ComposeError, compose, expand_macros

DATA = '| makeresults format=json data="[]"'


def test_base_search_becomes_a_search_command():
    c = compose('index=os sourcetype=linux_secure "Failed password"\n| stats count by src', DATA, {})
    assert c.search == f'{DATA}\n| search index=os sourcetype=linux_secure "Failed password"\n| stats count by src'
    assert c.notes == []


def test_explicit_search_keyword():
    c = compose("search index=os error | stats count", DATA, {})
    assert c.search == f"{DATA}\n| search index=os error | stats count"


def test_time_modifiers_are_removed():
    c = compose("index=os earliest=-15m latest=now error | stats count", DATA, {})
    assert "| search index=os error | stats count" in c.search
    assert len(c.notes) == 2 and "earliest=-15m" in c.notes[0]


def test_generating_commands_are_rejected():
    with pytest.raises(ComposeError, match=r"starts with \| tstats"):
        compose("| tstats count where index=os by host", DATA, {})
    with pytest.raises(ComposeError, match="doesn't parse"):
        compose('index=os "unterminated', DATA, {})


def test_macros_are_expanded_when_given_and_kept_otherwise():
    c = compose("`sysmon` EventCode=1 | `ctime(firstTime)`", DATA, {"sysmon": "index=edr sourcetype=sysmon"})
    assert "| search index=edr sourcetype=sysmon EventCode=1 | `ctime(firstTime)`" in c.search
    assert "| search `sysmon` EventCode=1" in compose("`sysmon` EventCode=1", DATA, {}).search
    assert expand_macros("`a`", {"a": "`b` x", "b": "index=y"}) == "index=y x"
    with pytest.raises(ComposeError, match="settle"):
        expand_macros("`a`", {"a": "`a`"})


def test_subsearches_on_real_data_are_noted():
    c = compose("index=os [search index=hr status=terminated | fields user] | stats count", DATA, {})
    assert any("subsearch reads real indexed data" in n for n in c.notes)
    quiet = compose("index=os | stats count | appendpipe [stats count | where count=0]", DATA, {})
    assert quiet.notes == []


def test_comments_survive():
    c = compose("index=os ``` note ``` error | stats count", DATA, {})
    assert "``` note ```" in c.search
