import pytest

from sigma2splunk.condition import And, Not, Or, Ref, expand, parse_condition
from sigma2splunk.errors import UnsupportedSigma


def test_parse_and_or_not_precedence():
    node = parse_condition("a and b or c")
    assert isinstance(node, Or)
    assert isinstance(node.nodes[0], And) and isinstance(node.nodes[1], Ref)


def test_parse_parentheses_and_not():
    node = parse_condition("not (a or b)")
    assert isinstance(node, Not) and isinstance(node.node, Or)


def test_quantifiers_expand():
    names = ["selection_a", "selection_b", "filter"]
    assert isinstance(expand(parse_condition("all of them"), names), And)
    assert isinstance(expand(parse_condition("1 of them"), names), Or)
    one = expand(parse_condition("1 of selection_*"), names)
    assert isinstance(one, Or) and {n.name for n in one.nodes} == {"selection_a", "selection_b"}
    allof = expand(parse_condition("all of selection_*"), names)
    assert isinstance(allof, And)


def test_single_match_quantifier_collapses():
    node = expand(parse_condition("1 of filter*"), ["filter1"])
    assert isinstance(node, Ref) and node.name == "filter1"


def test_unknown_selection_rejected():
    with pytest.raises(UnsupportedSigma, match="unknown selection"):
        expand(parse_condition("nope"), ["a"])


def test_n_of_unsupported():
    with pytest.raises(UnsupportedSigma, match="only 1 of / all of"):
        expand(parse_condition("2 of them"), ["a", "b"])


def test_no_matching_selection_pattern():
    with pytest.raises(UnsupportedSigma, match="matched no selections"):
        expand(parse_condition("1 of missing_*"), ["a"])


@pytest.mark.parametrize("bad", ["a and", "(a or b", "and a"])
def test_malformed_conditions(bad):
    with pytest.raises(UnsupportedSigma):
        parse_condition(bad)
