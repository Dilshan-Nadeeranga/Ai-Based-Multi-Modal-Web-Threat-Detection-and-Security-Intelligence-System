"""Unit and integration test suite for Component C1 Machine Learning Pipeline."""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.ml.dataset_loader import DatasetLoader
from app.ml.feature_extractor import FEATURE_NAMES, MlFeatureExtractor
from app.ml.model_service import MlInferenceService
from app.ml.pipeline import MlTrainingPipeline
from main import app

client = TestClient(app)


def test_feature_extractor_consistency():
    """Verify feature extractor consistency across dictionary, vector, and DataFrame methods."""
    extractor = MlFeatureExtractor()
    test_url = "https://login.paypal.account-verify.com/auth/login.php?user=123"

    feat_dict = extractor.extract_dict(test_url)
    feat_vec = extractor.extract_vector(test_url)
    feat_df = extractor.extract_dataframe([test_url])

    assert len(FEATURE_NAMES) == 57
    assert len(feat_dict) == 57
    assert feat_vec.shape == (57,)
    assert feat_df.shape == (1, 57)

    # Verify vector matches dict values exactly in order
    for idx, name in enumerate(FEATURE_NAMES):
        assert name in feat_dict
        assert feat_vec[idx] == pytest.approx(feat_dict[name], rel=1e-5)
        assert feat_df.iloc[0][name] == pytest.approx(feat_dict[name], rel=1e-5)


def test_dataset_loader_cleaning_and_deduplication(tmp_path: Path):
    """Verify dataset loader cleans malformed rows, normalizes labels, and deduplicates."""
    sample_csv = tmp_path / "test_raw.csv"
    sample_csv.write_text(
        "url,label,collection_date\n"
        "https://google.com,legitimate,2026-09-01\n"
        "https://google.com,clean,2026-09-01\n"  # Duplicate
        "http://paypal-scam.xyz/login,phishing,2026-09-02\n"
        "http://malware-dropper.top/bin,bad,2026-09-02\n"
        ",malicious,2026-09-03\n"  # Empty URL
        "http://valid.org/test,unknown_label,2026-09-03\n"  # Invalid label
    )

    loader = DatasetLoader(random_seed=42)
    df = loader.load_dataset(sample_csv)

    # Should contain exactly 3 valid cleaned, deduplicated URLs
    assert len(df) == 3
    assert set(df["label"].unique()) <= {0, 1}
    assert "registered_domain" in df.columns


def test_domain_grouped_split_leakage_prevention(tmp_path: Path):
    """Verify domain-grouped splitting ensures ZERO domain overlap across splits."""
    loader = DatasetLoader(random_seed=42)
    benchmark_path = Path("data/benchmark_urls.csv")
    assert benchmark_path.exists(), "Benchmark dataset must exist"

    df = loader.load_dataset(benchmark_path)
    splits = loader.split_dataset(df, test_size=0.2, val_size=0.1, strategy="domain_grouped")

    train_domains = set(splits.train_df["registered_domain"])
    val_domains = set(splits.val_df["registered_domain"])
    test_domains = set(splits.test_df["registered_domain"])

    # Strict Zero-Leakage checks
    assert len(train_domains.intersection(test_domains)) == 0, "Train and Test sets must have 0 domain overlap"
    assert len(train_domains.intersection(val_domains)) == 0, "Train and Val sets must have 0 domain overlap"
    assert len(val_domains.intersection(test_domains)) == 0, "Val and Test sets must have 0 domain overlap"


def test_pipeline_training_and_reports(tmp_path: Path):
    """Verify training pipeline trains all 4 models and generates valid comparison reports."""
    benchmark_path = Path("data/benchmark_urls.csv")
    trainer = MlTrainingPipeline(output_dir=tmp_path / "models", random_seed=42)

    report = trainer.run_training_pipeline(
        dataset_path=benchmark_path,
        test_size=0.2,
        val_size=0.1,
        split_strategy="domain_grouped",
        model_selection="all",
    )

    # 1. Verify required models evaluated (including baseline and improved RF)
    expected_models = {"random_forest", "random_forest_baseline", "decision_tree", "xgboost", "lightgbm"}
    assert set(report.models.keys()) == expected_models

    for mid, res in report.models.items():
        assert 0.0 <= res.accuracy <= 1.0
        assert 0.0 <= res.precision <= 1.0
        assert 0.0 <= res.recall <= 1.0
        assert 0.0 <= res.f1_score <= 1.0
        assert 0.0 <= res.roc_auc <= 1.0
        assert 0.0 <= res.false_positive_rate <= 1.0
        assert len(res.confusion_matrix) == 2
        assert len(res.confusion_matrix[0]) == 2
        assert res.avg_latency_ms >= 0.0
        assert res.training_time_sec >= 0.0

    # 2. Verify files written
    assert (tmp_path / "models" / "preprocessor.joblib").exists()
    assert (tmp_path / "models" / "best_model.joblib").exists()
    assert (tmp_path / "models" / "model_metadata.json").exists()
    assert (tmp_path / "models" / "model_comparison_report.json").exists()
    assert (tmp_path / "models" / "model_comparison_report.md").exists()


def test_random_forest_dedicated_training(tmp_path: Path):
    """Verify dedicated Random Forest training pipeline with class-imbalance weighting and latency benchmarking."""
    benchmark_path = Path("data/benchmark_urls.csv")
    trainer = MlTrainingPipeline(output_dir=tmp_path / "rf_models", random_seed=42)

    report = trainer.run_training_pipeline(
        dataset_path=benchmark_path,
        test_size=0.2,
        val_size=0.1,
        split_strategy="domain_grouped",
        model_selection="random_forest",
    )

    assert "random_forest" in report.models
    assert len(report.models) in (1, 2)
    rf_eval = report.models["random_forest"]
    assert "Random Forest" in rf_eval.model_name
    assert rf_eval.accuracy >= 0.8
    assert rf_eval.f1_score >= 0.8
    assert rf_eval.training_time_sec >= 0.0
    assert (tmp_path / "rf_models" / "random_forest.joblib").exists()


def test_large_dataset_preparer_pipeline(tmp_path: Path):
    """Verify LargeDatasetPreparer correctly processes, standardizes, deduplicates, and reports on data."""
    from app.ml.prepare_dataset import LargeDatasetPreparer

    raw_csv = tmp_path / "raw_urls_feed.csv"
    raw_csv.write_text(
        "url,status\n"
        "https://valid-target.com/home,legitimate\n"
        "https://valid-target.com/home,good\n"  # Duplicate
        "http://attack-vector.xyz/stealer.exe,malware\n"
        "http://credential-theft.top/auth,phishing\n"
        "http://corrupt.com,unknown_category\n"  # Must be dropped (no invented labels)
        "bad_short_url,malicious\n"  # Malformed URL (< 4 chars / no dots)
    )

    cleaned_csv = tmp_path / "cleaned_output.csv"
    report_json = tmp_path / "quality_report.json"
    preparer = LargeDatasetPreparer(random_seed=42)

    report = preparer.prepare_from_csv(
        input_csv=raw_csv,
        output_csv=cleaned_csv,
        url_col="url",
        label_col="status",
        chunk_size=10,
        report_json_path=report_json,
    )

    assert report.valid_records_retained == 3
    assert report.dropped_duplicates == 1
    assert report.dropped_unknown_labels == 1
    assert report.legitimate_count == 1
    assert report.malicious_count == 2
    assert report.unique_domains == 3
    assert cleaned_csv.exists()
    assert report_json.exists()


def test_domain_level_features_integration():
    """Verify feature extractor handles real domain telemetry when available and handles missing telemetry gracefully."""
    extractor = MlFeatureExtractor()

    # 1. With domain telemetry
    real_domain_data = {
        "domain_age_days": 120,
        "is_nrd": False,
        "has_dns_records": True,
    }
    vec_with_dom = extractor.extract_dict("https://example.com/test", domain_data=real_domain_data)
    assert vec_with_dom["domain_age_days"] == 120.0
    assert vec_with_dom["is_nrd"] == 0.0
    assert vec_with_dom["has_dns_records"] == 1.0
    assert vec_with_dom["has_domain_data"] == 1.0
    assert vec_with_dom["is_https"] == 1.0

    # 2. Without domain telemetry (raw URL only)
    vec_without_dom = extractor.extract_dict("http://example.com/test")
    assert vec_without_dom["domain_age_days"] == -1.0
    assert vec_without_dom["is_nrd"] == 0.0
    assert vec_without_dom["has_dns_records"] == 0.0
    assert vec_without_dom["has_domain_data"] == 0.0
    assert vec_without_dom["is_https"] == 0.0


def test_model_service_loading_and_inference():
    """Verify production inference service loads fitted model and predicts accurately."""
    service = MlInferenceService(model_dir="models")
    assert service.is_loaded is True
    assert service.model is not None
    assert service.preprocessor is not None

    # Test legitimate URL prediction
    legit_res = service.predict("https://www.google.com/search?q=cybersecurity")
    assert legit_res.is_model_loaded is True
    assert legit_res.predicted_label == "legitimate"
    assert legit_res.malicious_probability <= legit_res.decision_threshold
    assert legit_res.feature_count == 57
    assert legit_res.inference_time_ms > 0

    # Test malicious phishing URL prediction
    phish_res = service.predict("http://login.paypal.account-verification-support.com/auth/login.php")
    assert phish_res.is_model_loaded is True
    assert phish_res.predicted_label == "malicious"
    assert phish_res.malicious_probability >= phish_res.decision_threshold
    assert len(phish_res.top_risk_features) > 0


def test_model_service_invalid_and_empty_inputs():
    """Verify inference handles empty, whitespace, and non-ASCII inputs gracefully."""
    service = MlInferenceService(model_dir="models")

    # Empty string
    empty_res = service.predict("")
    assert empty_res.is_model_loaded is True
    assert empty_res.predicted_label in ["legitimate", "malicious"]

    # Whitespace only
    ws_res = service.predict("    ")
    assert ws_res.is_model_loaded is True

    # Punycode / unicode domain
    idn_res = service.predict("http://xn--apple-43a.com/verify")
    assert idn_res.is_model_loaded is True


def test_model_service_fallback_when_unloaded(tmp_path: Path):
    """Verify graceful fallback behavior when model files are not present."""
    empty_dir = tmp_path / "empty_models"
    empty_dir.mkdir()

    service = MlInferenceService(model_dir=empty_dir)
    assert service.is_loaded is False

    res = service.predict("https://example.com")
    assert res.is_model_loaded is False
    assert res.model_name is None
    assert res.malicious_probability == 0.0


def test_api_endpoints_ml_integration():
    """Verify FastAPI routes for direct ML prediction and model status."""
    # 1. Model status endpoint
    status_resp = client.get("/api/v1/ml-model-status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert "is_model_loaded" in status_data
    assert "metadata" in status_data

    # 2. Direct ML prediction endpoint
    pred_resp = client.post(
        "/api/v1/ml-predict",
        json={"url": "http://netflix-billing-issue-update.xyz/account/payment-information"},
    )
    assert pred_resp.status_code == 200
    pred_data = pred_resp.json()
    assert pred_data["is_model_loaded"] is True
    assert pred_data["predicted_label"] == "malicious"
    assert pred_data["feature_count"] == 57

    # 3. Empty URL validation error
    bad_resp = client.post("/api/v1/ml-predict", json={"url": ""})
    assert bad_resp.status_code == 400
