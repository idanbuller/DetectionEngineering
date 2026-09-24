from typing import List

import pytest

from spl_lint.config import Config
from spl_lint.linter import lint_text


@pytest.fixture
def ids():
    """Rule ids reported for a query, with every rule (including opt-in ones) enabled."""

    def _ids(query: str) -> List[str]:
        return [f.rule_id for f in lint_text(query, Config(select=["SPL"]))]

    return _ids
