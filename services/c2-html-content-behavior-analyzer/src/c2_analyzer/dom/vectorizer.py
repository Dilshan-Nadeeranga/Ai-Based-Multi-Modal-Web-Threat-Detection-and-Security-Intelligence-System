"""Assemble the DOM security feature vector.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from c2_analyzer.schemas.dom import DomFeatures
from c2_analyzer.schemas.parsed_page import ParsedPage

FEATURE_ORDER: tuple[str, ...] = tuple(DomFeatures.model_fields)


def extract_dom_features(html: str, page: ParsedPage) -> DomFeatures:
    """Compute all DOM features for one page."""
    raise NotImplementedError


def to_vector(features: DomFeatures) -> list[float]:
    """Flatten features in FEATURE_ORDER."""
    raise NotImplementedError
