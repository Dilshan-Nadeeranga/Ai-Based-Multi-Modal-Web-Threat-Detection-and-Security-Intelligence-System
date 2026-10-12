"""Tests for Part 7: Static JavaScript intent analyzer."""

import pytest

pytestmark = pytest.mark.skip(reason="Part 7 not implemented yet")


def test_placeholder(load_page):
    html = load_page("js_exfiltration.html")
    # TODO (Part 7): replace with real assertions.
    assert html
