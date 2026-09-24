from spl_lint.parser import MACRO, PLACEHOLDER, SUBSEARCH, parse


def names(q):
    return [c.name for c in q.root.commands]


def test_implicit_base_search_and_commands():
    q = parse("index=main error | stats count by host | sort 0 -count")
    assert names(q) == ["search", "stats", "sort"]
    assert q.root.commands[0].implicit
    assert not q.diagnostics


def test_explicit_search_and_leading_pipe():
    assert names(parse("search index=main")) == ["search"]
    q = parse("| tstats count where index=main by host")
    assert q.root.leading_pipe and names(q) == ["tstats"]


def test_pipes_inside_strings_regex_and_comments_do_not_split():
    q = parse('index=a | rex field=_raw "(?<x>a|b)" ``` a | b ``` | where match(x, "c|d")')
    assert names(q) == ["search", "rex", "where"]


def test_subsearch_is_parsed_recursively():
    q = parse("index=a [search index=b | fields user] | stats count")
    base = q.root.commands[0]
    assert names(q) == ["search", "stats"]
    assert len(base.subsearches) == 1
    assert [c.name for c in base.subsearches[0].commands] == ["search", "fields"]
    assert any(t.kind == SUBSEARCH for t in base.tokens())


def test_subsearch_may_start_with_generating_command():
    q = parse("index=a NOT [inputlookup allow.csv | fields user]")
    sub = q.root.commands[0].subsearches[0]
    assert [c.name for c in sub.commands] == ["inputlookup", "fields"]


def test_appendpipe_block_is_a_continuation():
    q = parse("index=a | stats count | appendpipe [stats count | where count=0]")
    sub = q.root.commands[2].subsearches[0]
    assert [c.name for c in sub.commands] == ["stats", "where"]


def test_macro_base_search_is_implicit_search():
    q = parse("`sysmon` EventCode=1 | stats count")
    first = q.root.commands[0]
    assert first.name == "search" and first.implicit
    assert first.tokens()[0].kind == MACRO


def test_macro_as_command():
    q = parse("index=a | `drop_dm_object_name(Processes)` | stats count")
    assert names(q) == ["search", "`macro`", "stats"]


def test_placeholders():
    toks = parse("%original_detection_search% | search user=$user$").root.commands[0].tokens()
    assert toks[0].kind == PLACEHOLDER


def test_escaped_quote_outside_string():
    q = parse('index=k8s annotation=*\\"privileged\\":true* | stats count')
    assert not q.diagnostics
    assert names(q) == ["search", "stats"]


def test_eval_tokens_split_on_dot():
    toks = parse("index=a | eval x=a.b").root.commands[1].tokens()
    assert [t.value for t in toks] == ["x", "=", "a", ".", "b"]


def test_diagnostics():
    assert [d.message for d in parse('index=a "open').diagnostics] == ["Unterminated string"]
    assert "Empty command between pipes" in [d.message for d in parse("index=a | | stats count").diagnostics]
    assert "Unclosed [ subsearch" in [d.message for d in parse("index=a [search index=b").diagnostics]
    assert "Unclosed (" in [d.message for d in parse("index=a | where (a=1").diagnostics]
    assert "Unmatched )" in [d.message for d in parse("index=a | where a=1)").diagnostics]
    assert "Unterminated ``` comment" in [d.message for d in parse("index=a ``` oops").diagnostics]


def test_suppression_directives():
    assert parse("index=a ``` spl-lint: disable=SPL204, SPL205 ```").suppressed == {"SPL204", "SPL205"}
    assert parse("index=a ``` spl-lint: disable ```").suppressed == {"all"}
    assert parse("index=a").suppressed is None
    reason = parse("index=a ``` spl-lint: disable=SPL204, missing-index -- lookup has 40 rows ```")
    assert reason.suppressed == {"SPL204", "MISSING-INDEX"}
