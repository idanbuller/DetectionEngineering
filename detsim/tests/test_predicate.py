from detsim.predicate import And, Cmp, Not, Or, Term, from_spl, matches


def ast(spl):
    return from_spl(spl).ast


def test_parse_and_or_not():
    node = ast('index=edr (a="1" OR b="2") NOT c="3"')
    assert isinstance(node, And)
    assert any(isinstance(n, Or) for n in node.nodes)
    assert any(isinstance(n, Not) for n in node.nodes)


def test_parse_comparison_and_wildcard_flag():
    node = from_spl('process="*/sh"').ast
    assert isinstance(node, Cmp) and node.field == "process" and node.wildcard and node.value == "*/sh"
    bare = from_spl("index=edr").ast
    assert isinstance(bare, Cmp) and bare.field == "index" and not bare.wildcard


def test_in_clause_becomes_or():
    node = from_spl("index IN (a, b, c) error").ast
    assert isinstance(node, And)
    assert any(isinstance(n, Or) and len(n.nodes) == 3 for n in node.nodes)


def test_keyword_term():
    node = from_spl('index=edr "Failed password"').ast
    assert any(isinstance(n, Term) for n in node.nodes)


def test_matcher_wildcards_and_case_insensitive():
    node = from_spl('process="*/certutil.exe" cmdline="*http*"').ast
    assert matches(node, {"process": "C:/X/certutil.exe", "cmdline": "certutil http://x"})
    assert not matches(node, {"process": "C:/X/cmd.exe", "cmdline": "certutil http://x"})


def test_matcher_not_and_numeric():
    assert matches(from_spl("count>5").ast, {"count": "9"})
    assert not matches(from_spl("count>5").ast, {"count": "3"})
    node = from_spl('a="1" NOT b="2"').ast
    assert matches(node, {"a": "1"})
    assert not matches(node, {"a": "1", "b": "2"})


def test_exists_and_negation_of_missing():
    assert matches(from_spl("field=*").ast, {"field": "anything"})
    assert not matches(from_spl("field=*").ast, {})
    assert matches(from_spl('NOT b="2"').ast, {})  # absent field satisfies NOT
