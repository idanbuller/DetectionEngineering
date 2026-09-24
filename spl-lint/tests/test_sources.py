import textwrap

from spl_lint.linter import lint_source
from spl_lint.sources import read_savedsearches, read_spl, read_yaml


def test_yaml_block_scalar_positions():
    content = textwrap.dedent(
        """\
        name: Brute force
        search: |
          index=auth action=failure
          | where user.name="root"
        """
    )
    [src] = read_yaml("d.yml", content, ["search"])
    assert src.name == "Brute force"
    [result] = lint_source(src)
    assert result.finding.rule_id == "SPL104"
    assert (result.line, result.column) == (4, 11)


def test_yaml_single_line_quoted_positions():
    content = "detections:\n  - title: t\n    spl: 'sourcetype=x error'\n"
    [src] = read_yaml("d.yml", content, ["search", "spl"])
    assert src.name == "t"
    [result] = lint_source(src)
    assert result.finding.rule_id == "SPL201"
    assert (result.line, result.column) == (3, 11)


def test_yaml_multiple_documents_and_non_string_values():
    content = "search: index=a | join x [search index=b]\n---\nsearch: 5\n---\nquery: index=c\n"
    sources = read_yaml("d.yml", content, ["search", "query"])
    assert [s.text for s in sources] == ["index=a | join x [search index=b]", "index=c"]


def test_savedsearches_conf_continuations():
    content = textwrap.dedent(
        """\
        [Failed logins]
        cron_schedule = */5 * * * *
        search = index=auth action=failure \\
        | join user [search index=hr] \\
        | stats count by user

        [Other]
        search = index=a
        """
    )
    first, second = read_savedsearches("savedsearches.conf", content)
    assert first.name == "Failed logins"
    assert first.text == "index=auth action=failure \n| join user [search index=hr] \n| stats count by user"
    [result] = lint_source(first)
    assert result.finding.rule_id == "SPL204"
    assert (result.line, result.column) == (4, 3)
    assert second.name == "Other" and second.text == "index=a"


def test_spl_file_positions():
    [src] = read_spl("q.spl", "index=a\n| sort -count\n| dedup user")
    [result] = lint_source(src)
    assert (result.line, result.column) == (2, 3)
