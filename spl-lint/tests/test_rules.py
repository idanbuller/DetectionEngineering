"""Edge cases beyond the documented examples, mostly things that must NOT be flagged."""

import pytest


@pytest.mark.parametrize(
    "query",
    [
        "index=a user=alice OR user=bob",
        "index=a mode=and",
        "index=a | where a=1 and b=2",  # eval-style commands accept lowercase
        'index=a user IN ("x", "y")',
        'index=a "or"',
    ],
)
def test_lowercase_boolean_negatives(ids, query):
    assert "SPL101" not in ids(query)


def test_lowercase_in_is_flagged(ids):
    assert "SPL101" in ids("index=a user in (alice, bob)")


@pytest.mark.parametrize(
    "query",
    [
        'index=a | where action="*"',  # literal "*" (e.g. an IAM policy action)
        'index=a | where command!="(*)"',
        'index=a | eval pattern="svc_*"',  # assignment, not comparison
        'index=a | eval x=if(y=1, "a*", "b")',
    ],
)
def test_wildcard_comparison_negatives(ids, query):
    assert "SPL102" not in ids(query)


@pytest.mark.parametrize(
    "query",
    [
        'index=a | eval x=if(user=="*admin", 1, 0)',
        'index=a | where user!="svc*"',
        'index=a | eval x=case(user="*admin*", 1)',
    ],
)
def test_wildcard_comparison_positives(ids, query):
    assert "SPL102" in ids(query)


def test_like_operator_form(ids):
    assert "SPL103" in ids('index=a | where user LIKE "adm*"')
    assert "SPL103" not in ids('index=a | where user LIKE "adm%"')


@pytest.mark.parametrize(
    "query",
    [
        "index=a | eval x='a.b'",
        "index=a | eval x=a . b",  # spaced concatenation is explicit
        'index=a | eval x=a."suffix"',
        "index=a | eval version=1.5",
        "index=a | eval 'a.b'=1",
        "index=a | stats count by a.b",  # fine outside eval expressions
    ],
)
def test_dotted_field_negatives(ids, query):
    assert "SPL104" not in ids(query)


def test_dotted_field_in_function_args(ids):
    assert ids("index=a | eval m=if(match(user.name, req.user), 1, 0)").count("SPL104") == 2


@pytest.mark.parametrize(
    "query",
    [
        "index=a | sort 0 -count",
        "index=a | sort limit=0 -count",
        "index=a | sort 100 x",
        "index=a | sort -count | head 5",
    ],
)
def test_sort_negatives(ids, query):
    assert "SPL106" not in ids(query)


@pytest.mark.parametrize(
    "query",
    [
        "index IN (a, b) error",
        "index::main error",
        "`my_index_macro` error",
        "%original_detection_search% | search user=x",
        "| tstats count where index=a by host",
        "| inputlookup users.csv",
    ],
)
def test_missing_index_negatives(ids, query):
    assert "SPL201" not in ids(query)


def test_missing_index_in_subsearch(ids):
    assert "SPL201" in ids("index=a [search sourcetype=b | fields user]")


def test_leading_wildcard_only_in_base_search(ids):
    assert "SPL203" in ids('index=a CommandLine="*mimikatz*"')
    assert "SPL203" not in ids('index=a | search CommandLine="*mimikatz*"')
    assert "SPL203" not in ids("index=a user=*")


def test_subsearch_truncation_skips_join_and_appendpipe(ids):
    assert "SPL206" not in ids("index=a | join user [search index=b]")
    assert "SPL206" not in ids("index=a | stats count | appendpipe [stats count]")
    assert "SPL206" in ids("index=a | append [search index=b]")


def test_spath_with_positional_path(ids):
    assert "SPL208" not in ids("index=a | spath output=x path=a.b")
    assert "SPL208" not in ids("index=a | spath a.b")
    assert "SPL208" in ids("index=a | spath input=body")


def test_table_at_end_is_fine(ids):
    assert "SPL209" not in ids("index=a | stats count by x | table x count | sort 0 -count")


def test_style_rule_is_opt_in():
    from spl_lint.linter import lint_text

    assert [f.rule_id for f in lint_text("index=a | STATS count BY user")] == []


def test_suppression_comment(ids):
    q = "index=a | join user [search index=b] ``` spl-lint: disable=SPL204 ```"
    assert "SPL204" not in ids(q)
    assert ids("index=a | join user [search index=b] ``` spl-lint: disable ```") == []
    assert "SPL201" not in ids("sourcetype=a ``` spl-lint: disable=missing-index -- why ```")


def test_findings_are_ordered_by_position(ids):
    from spl_lint.linter import lint_text

    findings = lint_text("sourcetype=x | join a [search index=b] | transaction c")
    assert [f.rule_id for f in findings] == ["SPL201", "SPL204", "SPL205"]
