"""Serve the Part 6A text models: page_text -> class probabilities.

Part 6: XLM-R content classification (6A, page level).

- XLM-R final model (``models/xlmr/<v>/final``) on CPU, ``torch.no_grad``, batched.
- TF-IDF baseline (``models/text_baseline/<v>/tfidf_logreg.joblib``).

Both are loaded LAZILY on the first prediction (and only once, behind a lock), so
the API starts in a second even though torch + transformers take several seconds to
import, and a missing model or a missing torch install only turns that model's
answer into ``available=false`` + "model not available: ..." - never a failed request.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import numpy as np

from c2_analyzer.nlp.common import BASELINE_DISPLAY, BASELINE_NAME, XLMR_DISPLAY, XlmrConfig
from c2_analyzer.schemas.nlp import TextModelOutput, TextPrediction


class _Unavailable(Exception):
    pass


class TextModels:
    """The text models of one dataset version (lazy, thread-safe, CPU)."""

    def __init__(
        self,
        version: str,
        xlmr_dir: Path,
        baseline_dir: Path,
        batch_size: int = 8,
        device: str = "cpu",
    ) -> None:
        self.version = version
        self.xlmr_dir = Path(xlmr_dir)  # .../models/xlmr/<v>/final
        self.baseline_dir = Path(baseline_dir)  # .../models/text_baseline/<v>
        self.batch_size = batch_size
        self.device = device
        self._lock = threading.Lock()
        self._xlmr: tuple | None = None
        self._xlmr_error: str | None = None
        self._baseline: dict | None = None
        self._baseline_error: str | None = None

    @classmethod
    def from_config(cls, version: str | None = None, config: XlmrConfig | None = None):
        config = config or XlmrConfig.load()
        version = version or config.inference["serving_version"]
        return cls(
            version,
            config.models_dir(version) / "final",
            config.baseline_models_dir(version),
            batch_size=int(config.inference["batch_size"]),
        )

    # ---- loading ----------------------------------------------------------------

    def _load_xlmr(self):
        with self._lock:
            if self._xlmr is None and self._xlmr_error is None:
                if not (self.xlmr_dir / "model.safetensors").is_file():
                    self._xlmr_error = (
                        f"model not available: no XLM-R model for {self.version} (train on "
                        "Colab, then scripts/train_xlmr.py import-model)"
                    )
                else:
                    try:
                        from c2_analyzer.nlp.model import load_classifier

                        model, tokenizer = load_classifier(self.xlmr_dir, self.device)
                        meta = json.loads((self.xlmr_dir / "metrics.json").read_text("utf-8"))
                        mapping = json.loads(
                            (self.xlmr_dir / "label_mapping.json").read_text("utf-8")
                        )
                        self._xlmr = (model, tokenizer, mapping["classes"], meta)
                    except ImportError as error:
                        self._xlmr_error = f"model not available: {error.name} is not installed"
                    except Exception as error:  # noqa: BLE001 - a broken model must not fail
                        self._xlmr_error = f"model not available: {type(error).__name__}: {error}"
        if self._xlmr is None:
            raise _Unavailable(self._xlmr_error)
        return self._xlmr

    def _load_baseline(self) -> dict:
        with self._lock:
            if self._baseline is None and self._baseline_error is None:
                path = self.baseline_dir / f"{BASELINE_NAME}.joblib"
                if not path.is_file():
                    self._baseline_error = (
                        f"model not available: no TF-IDF baseline for {self.version} (run "
                        f"scripts/train_xlmr.py baseline --version {self.version})"
                    )
                else:
                    try:
                        import joblib

                        self._baseline = joblib.load(path)
                    except Exception as error:  # noqa: BLE001
                        self._baseline_error = f"model not available: {type(error).__name__}"
        if self._baseline is None:
            raise _Unavailable(self._baseline_error)
        return self._baseline

    # ---- predicting -------------------------------------------------------------

    def _xlmr_outputs(self, texts: list[str]) -> list[TextModelOutput]:
        try:
            model, tokenizer, classes, meta = self._load_xlmr()
        except _Unavailable as error:
            return [self._missing("xlmr", XLMR_DISPLAY, str(error)) for _ in texts]
        from c2_analyzer.nlp.model import predict_proba
        from c2_analyzer.nlp.tokenizer import token_lengths

        max_length = int(meta.get("max_length", 512))
        proba = predict_proba(model, tokenizer, texts, max_length, self.batch_size, self.device)
        lengths = token_lengths(tokenizer, texts)
        return [
            self._output(
                "xlmr",
                XLMR_DISPLAY,
                classes,
                p,
                seed=meta.get("seed"),
                input_tokens=int(n),
                truncated=bool(n > max_length),
            )
            for p, n in zip(proba, lengths, strict=True)
        ]

    def _baseline_outputs(self, texts: list[str]) -> list[TextModelOutput]:
        try:
            bundle = self._load_baseline()
        except _Unavailable as error:
            return [self._missing(BASELINE_NAME, BASELINE_DISPLAY, str(error)) for _ in texts]
        from c2_analyzer.nlp.text_baseline import predict_proba

        classes = bundle["labels"]
        proba = predict_proba(bundle["pipeline"], texts, len(classes))
        return [self._output(BASELINE_NAME, BASELINE_DISPLAY, classes, p) for p in proba]

    def _missing(self, model: str, display: str, reason: str) -> TextModelOutput:
        return TextModelOutput(
            model=model,
            display_name=display,
            available=False,
            reason=reason,
            dataset_version=self.version,
        )

    def _output(self, model, display, classes, proba: np.ndarray, **extra) -> TextModelOutput:
        return TextModelOutput(
            model=model,
            display_name=display,
            available=True,
            predicted=classes[int(np.argmax(proba))],
            probabilities={c: round(float(p), 6) for c, p in zip(classes, proba, strict=True)},
            dataset_version=self.version,
            **extra,
        )

    def predict_many(self, texts: list[str], xlmr: bool = True) -> list[list[TextModelOutput]]:
        """Per text: [XLM-R output, TF-IDF output].

        ``xlmr=False`` (Part 9 /analyze with XLMR_ENABLED=false) answers XLM-R with
        ``available=false`` "disabled" and never loads torch."""
        texts = [text or "" for text in texts]
        if xlmr:
            xlmr_out = self._xlmr_outputs(texts)
        else:
            reason = "model disabled (XLMR_ENABLED=false)"
            xlmr_out = [self._missing("xlmr", XLMR_DISPLAY, reason) for _ in texts]
        baseline = self._baseline_outputs(texts)
        return [[a, b] for a, b in zip(xlmr_out, baseline, strict=True)]

    def warm_up(self, xlmr: bool = True) -> dict[str, str | None]:
        """Load the models now (API start-up) - model -> None if loaded, else the reason."""
        status: dict[str, str | None] = {}
        for name, enabled, load in (
            ("xlmr", xlmr, self._load_xlmr),
            (BASELINE_NAME, True, self._load_baseline),
        ):
            if not enabled:
                status[name] = "model disabled (XLMR_ENABLED=false)"
                continue
            try:
                load()
                status[name] = None
            except _Unavailable as error:
                status[name] = str(error)
        return status

    def model_info(self) -> dict[str, dict]:
        """Version facts of the loaded models (for model_versions / GET /ready)."""
        info: dict[str, dict] = {}
        if self._xlmr is not None:
            meta = self._xlmr[3]
            info["xlmr"] = {
                "seed": meta.get("seed"),
                "model_name": meta.get("model_name") or meta.get("base_model"),
                "max_length": meta.get("max_length"),
            }
        if self._baseline is not None:
            info[BASELINE_NAME] = {
                "trained_at": self._baseline.get("trained_at"),
                "C": self._baseline.get("params", {}).get("C"),
            }
        return info

    def predict(
        self, page_text: str, page_language: str | None = None, sample_id: str | None = None
    ) -> TextPrediction:
        return TextPrediction(
            sample_id=sample_id,
            page_language=page_language,
            page_text_chars=len(page_text or ""),
            models=self.predict_many([page_text])[0],
        )


class TextModelRegistry:
    """One lazily created ``TextModels`` per dataset version (the API's shared instance)."""

    def __init__(self, config: XlmrConfig | None = None) -> None:
        self._config = config
        self._models: dict[str, TextModels] = {}
        self._lock = threading.Lock()

    @property
    def config(self) -> XlmrConfig:
        if self._config is None:
            self._config = XlmrConfig.load()
        return self._config

    @property
    def serving_version(self) -> str:
        return self.config.inference["serving_version"]

    def get(self, version: str | None = None) -> TextModels:
        version = version or self.serving_version
        with self._lock:
            if version not in self._models:
                self._models[version] = TextModels.from_config(version, self.config)
            return self._models[version]
