from pathlib import Path

from spl_lint.docs import render_markdown

DOCS = Path(__file__).resolve().parents[1] / "docs" / "rules.md"


def test_rules_doc_is_up_to_date():
    assert DOCS.read_text() == render_markdown(), "run: python -m spl_lint.docs > docs/rules.md"
