"""Behavioral intent (Part 8) models.

Part 8: Behavioral intent mapping (sources -> sinks).

Part 8's input is Part 7's ``schemas.js.JsAnalysisResult`` (detections with
locations, arguments, enclosing functions and assigned variables).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


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
