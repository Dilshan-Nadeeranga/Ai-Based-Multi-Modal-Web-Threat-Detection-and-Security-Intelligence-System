"""Unified API request/response models.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Input to ``POST /api/v1/analyze``."""

    html: str
    url: str | None = None


class ModalityResults(BaseModel):
    """Per-modality results; ``None`` means the modality was unavailable."""

    dom: dict[str, Any] | None = None
    content: dict[str, Any] | None = None
    behavior: dict[str, Any] | None = None


class AnalysisResponse(BaseModel):
    """Unified tri-modal output."""

    verdict: str
    risk_score: float
    modalities: ModalityResults = Field(default_factory=ModalityResults)
    missing_modalities: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
