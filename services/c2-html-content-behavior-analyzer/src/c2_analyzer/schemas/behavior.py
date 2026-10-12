"""JS findings (Part 7) and behavioral intent (Part 8) models.

Part 7: Static JavaScript intent analyzer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class JsFinding(BaseModel):
    """A single dangerous API usage found in static JavaScript."""

    api: str
    category: str
    severity: str
    script_index: int
    line: int | None = None
    snippet: str | None = None


class JsFindings(BaseModel):
    """All static JS findings for a page."""

    findings: list[JsFinding] = Field(default_factory=list)
    scripts_analyzed: int = 0
    scripts_failed: int = 0


class SourceSinkFlow(BaseModel):
    """A sensitive source reaching a dangerous sink (Part 8)."""

    source: str
    sink: str
    pattern: str | None = None


class BehaviorResult(BaseModel):
    """Behavioral intent mapping output (Part 8)."""

    flows: list[SourceSinkFlow] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)
    intent_vector: dict[str, float] = Field(default_factory=dict)
