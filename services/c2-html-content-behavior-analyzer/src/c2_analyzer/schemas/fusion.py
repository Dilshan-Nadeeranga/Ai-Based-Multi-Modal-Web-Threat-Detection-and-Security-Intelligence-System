"""Fusion explanation of one dataset sample (dev inspector).

Part 9: Tri-modal fusion + ablation study (Batch A, task 5). The public unified
``/api/v1/analyze`` response is Batch B (``schemas/analysis.py``).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

FUSION_SCHEMA_VERSION = "fusion_v1"


class ArmProbabilities(BaseModel):
    """One arm's class probabilities for the page, as the fusion model reads them."""

    arm: str
    display: str
    available: bool
    used_by_model: bool = Field(description="the final fusion model reads this arm")
    source: str | None = Field(
        None,
        description="out-of-fold (train/val pages: a model trained on the OTHER CV folds) or "
        "final model (test pages: trained on train+val)",
    )
    predicted: str | None = None
    probabilities: dict[str, float] = Field(default_factory=dict)
    reason: str | None = None


class FusionDriver(BaseModel):
    name: str
    arm: str
    value: float | None = None
    contribution: float


class FusionExplanation(BaseModel):
    schema_version: str = FUSION_SCHEMA_VERSION
    sample_id: str
    dataset_version: str
    split: str
    true_label: str
    strategy: str
    strategy_display: str
    arms: list[ArmProbabilities]
    missing_arms: list[str] = Field(default_factory=list)
    probabilities: dict[str, float]
    predicted: str
    benign_threshold: float = Field(description="benign if P(benign) >= this (OOF FPR <= target)")
    benign_fpr_target: float
    predicted_at_threshold: str
    driver_method: str
    arm_contributions: dict[str, float] = Field(
        description="contribution of each arm towards the predicted class"
    )
    driving_arm: str
    top_drivers: list[FusionDriver] = Field(default_factory=list)
    note: str
