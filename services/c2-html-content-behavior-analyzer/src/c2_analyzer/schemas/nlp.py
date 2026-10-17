"""Text-model prediction of one page (Part 6A output).

Part 6: XLM-R content classification (6A, page level).

``TextPrediction`` holds one ``TextModelOutput`` per text model (XLM-R and the TF-IDF
baseline). A missing model is NOT an error: ``available=false`` + ``reason`` (e.g.
"model not available: train on Colab, then import-model"), so the API and the
inspector keep working before the Colab run and Part 9 can list the modality as
missing.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

TEXT_PREDICTION_SCHEMA = "textpred_v1"


class TextModelOutput(BaseModel):
    model: str  # "xlmr" | "tfidf_logreg"
    display_name: str
    available: bool
    reason: str | None = None  # why not available
    predicted: str | None = None
    probabilities: dict[str, float] = Field(default_factory=dict)  # class -> probability
    dataset_version: str | None = None  # the model's training data version
    seed: int | None = None  # XLM-R: the final model's seed
    input_tokens: int | None = None  # XLM-R: tokens of page_text before truncation
    truncated: bool | None = None  # XLM-R: page_text longer than max_length tokens


class TextPrediction(BaseModel):
    schema_version: str = TEXT_PREDICTION_SCHEMA
    sample_id: str | None = None
    page_language: str | None = None  # Part 5A detected page language
    page_text_chars: int = 0
    models: list[TextModelOutput] = Field(default_factory=list)
    true_label: str | None = None  # dev endpoint only
    split: str | None = None  # dev endpoint only
