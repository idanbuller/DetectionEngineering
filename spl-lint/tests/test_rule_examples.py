"""Every rule's documented bad example must trigger it, and its good example must be clean."""

import pytest

from spl_lint.rules import all_rules

RULES = all_rules()


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_bad_example_triggers_rule(rule, ids):
    assert rule.id in ids(rule.bad)


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_good_example_is_clean(rule, ids):
    assert ids(rule.good) == []


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_rule_metadata_complete(rule):
    assert rule.id and rule.name and rule.category and rule.summary and rule.doc()
    assert rule.bad and rule.good
