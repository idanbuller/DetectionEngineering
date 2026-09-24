import textwrap

import pytest
import yaml

from synthlog.engine import generate
from synthlog.spec import parse_spec


@pytest.fixture
def build():
    """Parse a YAML spec string and generate its dataset."""

    def _build(text: str, background: bool = True):
        return generate(parse_spec(yaml.safe_load(textwrap.dedent(text))), include_background=background)

    return _build
