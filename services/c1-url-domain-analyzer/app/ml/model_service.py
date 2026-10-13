"""Inference service for loading trained Machine Learning models without retraining on requests."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd

from app.ml.feature_extractor import FEATURE_NAMES, MlFeatureExtractor
from app.schemas.url_schema import MlPredictionResult, UrlLexicalFeatures

logger = logging.getLogger(__name__)


class MlInferenceService:
    """Production inference engine loading pre-trained classifiers into memory."""

    def __init__(
        self,
        model_dir: Union[str, Path] = "models",
    ) -> None:
        self.model_dir = Path(model_dir)
        self.feature_extractor = MlFeatureExtractor()
        self.model: Optional[Any] = None
        self.preprocessor: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.is_loaded: bool = False

        self.load_model()

    def load_model(self) -> bool:
        """Load serialized preprocessor and best-performing model into memory."""
        model_path = self.model_dir / "best_model.joblib"
        preprocessor_path = self.model_dir / "preprocessor.joblib"
        metadata_path = self.model_dir / "model_metadata.json"

        if not model_path.exists() or not preprocessor_path.exists():
            logger.warning(
                "Trained ML model artifacts not found at '%s'. Operating in heuristic-only mode until trained.",
                self.model_dir,
            )
            self.is_loaded = False
            return False

        try:
            self.model = joblib.load(model_path)
            self.preprocessor = joblib.load(preprocessor_path)

            if metadata_path.exists():
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            else:
                self.metadata = {
                    "model_name": self.model.__class__.__name__,
                    "optimal_threshold": 0.5,
                }

            self.is_loaded = True
            logger.info(
                "Successfully loaded ML model '%s' with threshold %.2f",
                self.metadata.get("model_name", "Unknown"),
                self.metadata.get("optimal_threshold", 0.5),
            )
            return True
        except Exception as exc:
            logger.error("Failed to load ML model artifact from disk: %s", exc)
            self.is_loaded = False
            return False

    def predict(
        self,
        raw_url: str,
        lexical_features: Optional[UrlLexicalFeatures] = None,
        domain_data: Optional[Dict[str, Any]] = None,
    ) -> MlPredictionResult:
        """Execute fast, single-URL machine learning inference."""
        if not self.is_loaded or self.model is None or self.preprocessor is None:
            return MlPredictionResult(
                is_model_loaded=False,
                model_name=None,
                malicious_probability=0.0,
                predicted_label="legitimate",
                decision_threshold=0.5,
                confidence=0.0,
                inference_time_ms=0.0,
                feature_count=0,
                top_risk_features=[],
            )

        t0 = time.perf_counter()

        # 1. Extract feature dictionary and vector (incorporating domain data if present)
        feat_dict = self.feature_extractor.extract_dict(raw_url, domain_data=domain_data)
        df_input = pd.DataFrame([[feat_dict[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

        # 2. Transform through fitted preprocessing pipeline
        vector_proc = self.preprocessor.transform(df_input)

        # 3. Predict class probability
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(vector_proc)[0]
            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            raw_pred = self.model.predict(vector_proc)[0]
            malicious_prob = float(raw_pred)

        threshold = float(self.metadata.get("optimal_threshold", 0.5))
        is_malicious = malicious_prob >= threshold
        label = "malicious" if is_malicious else "legitimate"

        # Confidence is distance from decision boundary
        confidence = round(abs(malicious_prob - 0.5) * 200.0, 1)

        # 4. Extract top contributing risk features
        top_risk_features = self._identify_top_risk_features(feat_dict)

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        return MlPredictionResult(
            is_model_loaded=True,
            model_name=self.metadata.get("model_name", self.model.__class__.__name__),
            malicious_probability=round(malicious_prob, 4),
            predicted_label=label,
            decision_threshold=round(threshold, 4),
            confidence=confidence,
            inference_time_ms=latency_ms,
            feature_count=len(FEATURE_NAMES),
            top_risk_features=top_risk_features,
        )

    def _identify_top_risk_features(self, feat_dict: Dict[str, float]) -> List[str]:
        """Find standout malicious signals among extracted features."""
        signals = []
        if feat_dict.get("suspicious_keyword_count", 0) > 0:
            signals.append(f"Suspicious security keywords detected (count: {int(feat_dict['suspicious_keyword_count'])})")
        if feat_dict.get("is_ip_address", 0) > 0:
            signals.append("Direct IP address used as hostname")
        if feat_dict.get("has_homoglyphs", 0) > 0:
            signals.append("Unicode confusable / homoglyph characters present")
        if feat_dict.get("is_punycode", 0) > 0:
            signals.append("Punycode (xn--) internationalized domain encoding")
        if feat_dict.get("url_entropy", 0) > 4.2:
            signals.append(f"Elevated URL Shannon entropy ({feat_dict['url_entropy']:.2f} bits/char)")
        if feat_dict.get("dga_label_entropy", 0) >= 3.6:
            signals.append(f"Algorithmic DGA label entropy ({feat_dict['dga_label_entropy']:.2f} bits/char)")
        if feat_dict.get("has_at_symbol", 0) > 0:
            signals.append("Misleading @ symbol in URL authority")
        if feat_dict.get("is_double_encoded", 0) > 0:
            signals.append("Double percent-encoding evasion attempt")
        if feat_dict.get("digit_ratio", 0) > 0.25:
            signals.append(f"High numeric digit ratio ({(feat_dict['digit_ratio'] * 100):.1f}%)")
        return signals[:5]


# Process-wide singleton
_ml_service_instance: Optional[MlInferenceService] = None


def get_ml_service(model_dir: Union[str, Path] = "models") -> MlInferenceService:
    """Return process-wide singleton for ML inference service."""
    global _ml_service_instance
    if _ml_service_instance is None:
        _ml_service_instance = MlInferenceService(model_dir=model_dir)
    return _ml_service_instance
