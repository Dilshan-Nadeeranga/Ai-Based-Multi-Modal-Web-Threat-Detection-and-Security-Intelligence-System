"""Output of the DOM baseline classifier for one page (Part 4).

Used by ``scripts/train_dom_baseline.py predict`` and the dev endpoint
``GET /api/v1/dev/samples/{id}/dom-prediction`` (inspector card "DOM baseline
prediction"). A PILOT prediction (v0.1: 3 of 5 classes) can only ever answer
one of the trained classes - ``classes`` says which.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FeatureContribution(BaseModel):
    """One feature's push on the predicted class (positive = towards it)."""

    feature: str
    name: str  # human-readable: first sentence of the dictionary description + [feature]
    description: str
    value: float  # the page's feature value
    contribution: float
    direction: str  # "towards" | "away"
    method: str  # "SHAP (TreeExplainer)" | "coefficient x z-score"
    text: str  # plain English, e.g. "... [null_link_ratio] = 0.4 pushes towards phishing"


class ModelPrediction(BaseModel):
    """One model's answer."""

    model: str  # logreg | random_forest | xgboost
    display_name: str
    predicted: str
    probabilities: dict[str, float]  # class -> probability (sums to 1)
    cv_macro_f1: float | None = None


class DomPrediction(BaseModel):
    """All baselines' predictions for one page + the best model's explanation."""

    sample_id: str | None = None
    dataset_version: str  # the version the models were trained on
    feature_set_version: str
    classes: list[str]
    excluded_classes: dict[str, int] = Field(default_factory=dict)
    pilot: bool = False
    best_model: str  # by CV macro-F1
    predicted: str  # the best model's answer
    probabilities: dict[str, float]  # the best model's probabilities
    models: list[ModelPrediction]
    explained_model: str
    contributions: list[FeatureContribution]
    # dataset samples only (from the split / evaluation)
    true_label: str | None = None
    split: str | None = None  # train | val | test | excluded
    misclassified_test: bool | None = None  # only for test pages
    features_source: str | None = None  # stored | on-the-fly | computed
