"""Dangerous API detectors (rules in configs/js_rules.yaml).

Part 7: Static JavaScript intent analyzer.
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.behavior import JsFinding, JsFindings


def detect(ast: Any, script_index: int = 0) -> list[JsFinding]:
    """Find eval, Function, document.write, innerHTML, fetch, XHR, form.submit,
    redirects, cookie, storage and clipboard usage."""
    raise NotImplementedError


def analyze_scripts(scripts: list[str]) -> JsFindings:
    """Parse and run detectors on every script."""
    raise NotImplementedError
