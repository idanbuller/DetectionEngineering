import pytest
import yaml

from sigma2splunk.errors import UnsupportedSigma
from sigma2splunk.mapping import Mapping, Resolved
from sigma2splunk.render import render_spl
from sigma2splunk.sigma import parse_rule

RESOLVED = Resolved(index="edr", sourcetype="sysmon", base=None, field_map={})


def spl(detection_body, logsource="{}", resolved=RESOLVED, field_map=None):
    rule = parse_rule("r.yml", yaml.safe_load(f"title: R\nlogsource: {logsource}\ndetection:\n{detection_body}\n"))
    r = Resolved(resolved.index, resolved.sourcetype, resolved.base, field_map or {})
    return render_spl(rule, Mapping(), r)


def body(text):
    return "\n".join("  " + line for line in text.strip("\n").splitlines())


def test_plain_and_list_values():
    out, _ = spl(
        body("""
selection:
  Image: cmd.exe
  User:
    - alice
    - bob
condition: selection
""")
    )
    assert out == 'index=edr sourcetype="sysmon" (Image="cmd.exe" AND (User="alice" OR User="bob"))'


def test_string_modifiers():
    out, _ = spl(body("sel:\n    a|contains: x\n    b|startswith: y\n    c|endswith: z\ncondition: sel"))
    assert 'a="*x*"' in out and 'b="y*"' in out and 'c="*z"' in out


def test_all_modifier_is_and():
    out, _ = spl(body("sel:\n    CommandLine|contains|all:\n      - foo\n      - bar\ncondition: sel"))
    assert '(CommandLine="*foo*" AND CommandLine="*bar*")' in out


def test_numeric_and_comparison():
    out, _ = spl(body("sel:\n    Port: 443\n    Count|gt: 10\ncondition: sel"))
    assert "Port=443" in out and "Count>10" in out


def test_null_is_field_absent():
    out, _ = spl(body("sel:\n    TargetFilename: null\ncondition: sel"))
    assert 'NOT TargetFilename="*"' in out


def test_keywords_are_full_text_or():
    out, _ = spl(body("keywords:\n    - Failed password\n    - authentication failure\ncondition: keywords"))
    assert out.endswith('("Failed password" OR "authentication failure")')


def test_wildcards_and_backslashes_escaped():
    out, _ = spl(body("sel:\n    Image|endswith: '\\powershell.exe'\ncondition: sel"))
    assert 'Image="*\\\\powershell.exe"' in out  # backslash doubled for Splunk


def test_escaped_wildcard_noted():
    out, notes = spl(body("sel:\n    a: 'foo\\*bar'\ncondition: sel"))
    assert any("literal" in n for n in notes)


def test_question_mark_approximated():
    out, notes = spl(body("sel:\n    a: 'fo?bar'\ncondition: sel"))
    assert 'a="fo*bar"' in out and any("single char" in n for n in notes)


def test_field_mapping_applied():
    out, _ = spl(body("sel:\n    Image: x\ncondition: sel"), field_map={"Image": "process_path"})
    assert "process_path=" in out and "Image=" not in out


def test_not_and_nested_condition():
    out, _ = spl(
        body("""
sel: {a: 1}
filter: {b: 2}
condition: sel and not filter
""")
    )
    assert out == 'index=edr sourcetype="sysmon" (a=1 AND NOT (b=2))'


def test_list_of_maps_is_or():
    out, _ = spl(
        body("""
sel:
  - {a: 1}
  - {b: 2}
condition: sel
""")
    )
    assert "(a=1 OR b=2)" in out


@pytest.mark.parametrize("mod", ["re", "cidr", "base64", "fieldref"])
def test_unsupported_modifiers_raise(mod):
    with pytest.raises(UnsupportedSigma):
        spl(body(f"sel:\n    a|{mod}: x\ncondition: sel"))


def test_no_index_notes_and_still_renders():
    out, notes = spl(body("sel: {a: 1}\ncondition: sel"), resolved=Resolved(None, None, None, {}))
    assert out == "a=1" and any("no index" in n for n in notes)


def test_base_filter_included():
    out, _ = spl(body("sel: {a: 1}\ncondition: sel"), resolved=Resolved("edr", "st", "EventCode=1", {}))
    assert out == 'index=edr sourcetype="st" EventCode=1 a=1'
