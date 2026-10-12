"""Form features: password, email/user, hidden fields, external actions.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from c2_analyzer.schemas.parsed_page import ParsedPage


def form_features(page: ParsedPage) -> dict[str, int]:
    """Counts of forms, password/email/hidden inputs and external form actions."""
    raise NotImplementedError
