import pytest
import yaml

from sigma2splunk.sigma import SigmaError, load_rules, parse_rule


def parse(body):
    return parse_rule("r.yml", yaml.safe_load(body))


def test_parse_basic_fields():
    r = parse("""
title: Test Rule
id: abc-123
description: does a thing
level: high
status: stable
author: me
references: [https://example.com]
falsepositives: [noise]
tags: [attack.execution, attack.t1059.001, attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image: x}
  condition: selection
""")
    assert r.title == "Test Rule" and r.id == "abc-123" and r.level == "high"
    assert r.logsource.product == "windows" and r.logsource.category == "process_creation"
    assert r.techniques == ["T1059", "T1059.001"]
    assert list(r.selections) == ["selection"]


def test_condition_list_becomes_or():
    r = parse("logsource: {}\ndetection:\n  a: {x: 1}\n  b: {y: 2}\n  condition: [a, b]\n")
    assert r.condition == "(a) or (b)"


def test_missing_detection_errors():
    with pytest.raises(SigmaError, match="detection block"):
        parse("title: x\nlogsource: {}\n")


def test_load_rules_skips_global_collection_docs(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text(
        "action: global\nlogsource: {product: windows}\n---\n"
        "title: R\nlogsource: {service: sysmon}\ndetection:\n  sel: {Image: x}\n  condition: sel\n"
    )
    rules = load_rules(str(p))
    assert len(rules) == 1 and rules[0].title == "R"
