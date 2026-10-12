"""DomFeatures: the DOM security feature set.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from pydantic import BaseModel


class DomFeatures(BaseModel):
    """Structural features extracted from a page's DOM."""

    node_count: int = 0
    max_depth: int = 0
    form_count: int = 0
    password_field_count: int = 0
    email_or_user_field_count: int = 0
    hidden_field_count: int = 0
    external_form_action_count: int = 0
    iframe_count: int = 0
    hidden_iframe_count: int = 0
    script_count: int = 0
    external_script_count: int = 0
    hidden_element_count: int = 0
    internal_link_count: int = 0
    external_link_count: int = 0
    external_link_ratio: float = 0.0
