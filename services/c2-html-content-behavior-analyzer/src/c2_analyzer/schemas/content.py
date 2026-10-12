"""ContentResult: multilingual content analysis output.

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ContentResult(BaseModel):
    """Language + social-engineering intent prediction for a page's text."""

    language: str | None = None
    intent: str | None = None
    intent_scores: dict[str, float] = Field(default_factory=dict)
    threat_scores: dict[str, float] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
