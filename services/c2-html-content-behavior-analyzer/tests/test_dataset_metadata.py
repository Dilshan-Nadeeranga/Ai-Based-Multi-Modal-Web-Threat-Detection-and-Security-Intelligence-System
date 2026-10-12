"""Tests for Part 1 Batch A: metadata schema, MetadataStore and the build_metadata CLI.

All tests use pytest's tmp_path, so the real data/ folder is never touched.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from c2_analyzer.config import (
    get_labels,
    get_languages,
    get_quality_flags,
    get_sources,
    project_root,
)
from c2_analyzer.dataset.metadata import DuplicateSampleError, MetadataStore, record_to_row
from c2_analyzer.schemas.dataset import FetchMode, SampleMetadata
from c2_analyzer.utils.hashing import sha256_bytes, sha256_file

ROOT = project_root()
SCRIPT = ROOT / "scripts" / "build_metadata.py"
FIXTURE_HTML = ROOT / "tests" / "fixtures" / "sample_pages" / "benign_simple.html"


# ---- helpers ---------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> MetadataStore:
    return MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")


def write_sample(store: MetadataStore, label: str, number: int, content: str) -> SampleMetadata:
    """Create a raw file and a matching valid record (not yet added to the store)."""
    sample_id = f"c2_{label}_{number:06d}"
    file = store.raw_dir / label / f"{sample_id}.html"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content, encoding="utf-8")
    return SampleMetadata(
        sample_id=sample_id,
        file_path=f"{label}/{file.name}",
        label=label,
        language="en",
        source="manual",
        source_url=f"https://example.com/{sample_id}",
        collection_date=date(2026, 1, 15),
        sha256=sha256_file(file),
    )


def valid_fields(**overrides: object) -> dict:
    fields = {
        "sample_id": "c2_phishing_000001",
        "file_path": "phishing/c2_phishing_000001.html",
        "label": "phishing",
        "language": "si",
        "source": "phishtank",
        "source_url": "https://bad.example/login",
        "collection_date": "2026-01-15",
        "sha256": "a" * 64,
    }
    fields.update(overrides)
    return fields


# ---- schema: accepted / rejected -------------------------------------------


def test_valid_record_accepted():
    record = SampleMetadata(**valid_fields())
    assert record.verified is False
    assert record.collection_date == date(2026, 1, 15)


def test_sha256_is_normalised_to_lowercase():
    assert SampleMetadata(**valid_fields(sha256="A" * 64)).sha256 == "a" * 64


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"sample_id": "phishing_000001"}, id="sample_id-no-prefix"),
        pytest.param({"sample_id": "c2_phishing_1"}, id="sample_id-not-6-digits"),
        pytest.param({"sample_id": "c2_benign_000001"}, id="sample_id-label-mismatch"),
        pytest.param({"sha256": "abc123"}, id="sha256-too-short"),
        pytest.param({"sha256": "g" * 64}, id="sha256-not-hex"),
        pytest.param(
            {"collection_date": (date.today() + timedelta(days=1)).isoformat()}, id="future-date"
        ),
        pytest.param(
            {"label": "spam", "sample_id": "c2_spam_000001", "file_path": "spam/x.html"},
            id="unknown-label",
        ),
        pytest.param({"language": "fr"}, id="unknown-language"),
        pytest.param({"source": "google"}, id="unknown-source"),
        pytest.param({"source_url": "bad.example/login"}, id="url-without-scheme"),
        pytest.param({"file_path": "benign/c2_phishing_000001.html"}, id="file-in-wrong-folder"),
        pytest.param({"file_path": "../secret.html"}, id="file-path-escapes"),
        pytest.param({"verified": True}, id="verified-without-verified_by"),
        pytest.param({"lable": "phishing"}, id="unknown-field"),
        pytest.param({"fetch_mode": "crawler"}, id="unknown-fetch-mode"),
        pytest.param({"http_status": 999}, id="http-status-out-of-range"),
        pytest.param({"final_url": "ftp://x.example/"}, id="final-url-not-http"),
        pytest.param({"quality_flag": "broken"}, id="unknown-quality-flag"),
        pytest.param({"cluster_id": "cluster7"}, id="bad-cluster-id"),
        pytest.param({"excluded": True}, id="excluded-without-reason"),
        pytest.param({"exclusion_reason": "empty"}, id="reason-without-excluded"),
        pytest.param({"label_original": "phishing"}, id="label_original-same-as-label"),
        pytest.param({"label_original": "spam"}, id="unknown-label_original"),
        pytest.param(  # relabelled, but the id does not come from label_original
            {"label": "benign", "file_path": "benign/c2_phishing_000001.html",
             "label_original": "crypto_scam"},
            id="relabel-id-mismatch",
        ),  # fmt: skip
    ],
)
def test_invalid_record_rejected(overrides):
    with pytest.raises(ValidationError):
        SampleMetadata(**valid_fields(**overrides))


# ---- JSON Schema and folders stay in sync with configs ---------------------


def test_json_schema_matches_model_and_configs():
    schema = json.loads((ROOT / "data" / "metadata" / "dataset_schema.json").read_text("utf-8"))
    properties = schema["properties"]

    assert set(properties) == set(SampleMetadata.model_fields)
    required = {name for name, field in SampleMetadata.model_fields.items() if field.is_required()}
    assert set(schema["required"]) == required

    assert properties["label"]["enum"] == list(get_labels())
    assert properties["language"]["enum"] == list(get_languages())
    assert properties["source"]["enum"] == list(get_sources())
    assert properties["fetch_mode"]["enum"] == list(get_args(FetchMode))
    assert properties["quality_flag"]["enum"] == list(get_quality_flags())
    assert properties["label_original"]["enum"] == [*get_labels(), None]
    for field in ("sample_id", "file_path", "is_duplicate_of"):
        labels_in_pattern = re.search(r"\((.*?)\)", properties[field]["pattern"]).group(1)
        assert labels_in_pattern.split("|") == list(get_labels()), field


def test_raw_folders_match_labels():
    folders = {path.name for path in (ROOT / "data" / "raw").iterdir() if path.is_dir()}
    assert folders == set(get_labels())


# ---- MetadataStore -----------------------------------------------------------


def test_fetch_fields_accepted():
    record = SampleMetadata(
        **valid_fields(
            fetch_mode="static",
            final_url="https://bad.example/login2",
            http_status=200,
            content_type="text/html; charset=utf-8",
        )
    )
    assert record.fetch_mode == "static"
    assert SampleMetadata(**valid_fields()).fetch_mode == "manual"  # default


def test_batch_c_fields_defaults_and_relabelled_sample():
    record = SampleMetadata(**valid_fields())
    assert (record.quality_flag, record.excluded, record.cluster_id) == ("ok", False, None)

    relabelled = SampleMetadata(
        **valid_fields(
            label="benign",
            file_path="benign/c2_phishing_000001.html",  # file moved, id kept
            label_original="phishing",
            cluster_id="cl_000007",
            excluded=True,
            exclusion_reason="error_page",
        )
    )
    assert relabelled.sample_id == "c2_phishing_000001" and relabelled.label == "benign"


def test_load_upgrades_batch_b_header_with_defaults(store):
    """A metadata.csv written by Batch B (no cleaning columns) loads with defaults."""
    new_fields = ("cluster_id", "quality_flag", "excluded", "exclusion_reason", "label_original")
    old_columns = [c for c in SampleMetadata.model_fields if c not in new_fields]
    record = write_sample(store, "phishing", 1, "<p>a</p>")
    row = record_to_row(record)
    old_csv = ",".join(old_columns) + "\n" + ",".join(row[c] for c in old_columns) + "\n"
    store.csv_path.parent.mkdir(parents=True)
    store.csv_path.write_text(old_csv, encoding="utf-8")

    assert store.df.loc[0, "quality_flag"] == "ok" and store.df.loc[0, "excluded"] == "false"
    assert store.get(record.sample_id).quality_flag == "ok"
    assert store.validate_all() == []


def test_load_upgrades_old_header_without_fetch_columns(store):
    """A metadata.csv written by Batch A (no fetch_* columns) still loads."""
    new_fields = ("fetch_mode", "final_url", "http_status", "content_type")
    old_columns = [c for c in SampleMetadata.model_fields if c not in new_fields]
    record = write_sample(store, "phishing", 1, "<p>a</p>")
    row = record_to_row(record)
    old_csv = ",".join(old_columns) + "\n" + ",".join(row[c] for c in old_columns) + "\n"
    store.csv_path.parent.mkdir(parents=True)
    store.csv_path.write_text(old_csv, encoding="utf-8")
    assert store.get(record.sample_id).fetch_mode == "manual"
    store.save()
    header = store.csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",") == list(SampleMetadata.model_fields)


def test_load_rejects_unknown_columns(store):
    store.csv_path.parent.mkdir(parents=True)
    store.csv_path.write_text("sample_id,whatever\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Fix the header"):
        store.load()


def test_load_creates_csv_with_header(store):
    df = store.load()
    assert df.empty
    header = store.csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",") == list(SampleMetadata.model_fields)


def test_next_sample_id_increments_per_label(store):
    assert store.next_sample_id("phishing") == "c2_phishing_000001"
    store.add(write_sample(store, "phishing", 1, "<p>a</p>"))
    store.add(write_sample(store, "phishing", 2, "<p>b</p>"))
    assert store.next_sample_id("phishing") == "c2_phishing_000003"
    assert store.next_sample_id("benign") == "c2_benign_000001"
    # label names containing "_" are handled too
    store.add(write_sample(store, "fake_ecommerce", 7, "<p>c</p>"))
    assert store.next_sample_id("fake_ecommerce") == "c2_fake_ecommerce_000008"


def test_duplicate_sha256_rejected(store):
    store.add(write_sample(store, "phishing", 1, "<p>same</p>"))
    duplicate = write_sample(store, "benign", 1, "<p>same</p>")
    with pytest.raises(DuplicateSampleError, match="c2_phishing_000001"):
        store.add(duplicate)
    assert len(store.df) == 1


def test_duplicate_sample_id_rejected(store):
    store.add(write_sample(store, "phishing", 1, "<p>a</p>"))
    with pytest.raises(DuplicateSampleError, match="already exists"):
        store.add(write_sample(store, "phishing", 1, "<p>different</p>"))


def test_same_source_url_only_warns(store):
    first = write_sample(store, "phishing", 1, "<p>v1</p>")
    second = write_sample(store, "phishing", 2, "<p>v2</p>").model_copy(
        update={"source_url": first.source_url}
    )
    assert store.add(first) == []
    warnings = store.add(second)
    assert len(warnings) == 1 and "c2_phishing_000001" in warnings[0]


def test_save_and_reload_round_trip(store):
    record = write_sample(store, "crypto_scam", 1, "<p>x</p>").model_copy(
        update={"notes": 'has "quotes", commas'}
    )
    store.add(record)
    store.save()

    reloaded = MetadataStore(store.csv_path, store.raw_dir)
    assert reloaded.get(record.sample_id) == record
    # atomic save leaves no temporary files behind
    assert [path.name for path in store.csv_path.parent.iterdir()] == ["metadata.csv"]


def test_get_update_and_filter(store):
    store.add(write_sample(store, "phishing", 1, "<p>a</p>"))
    store.add(write_sample(store, "benign", 1, "<p>b</p>"))

    with pytest.raises(KeyError):
        store.get("c2_phishing_000099")

    updated = store.update(
        "c2_phishing_000001",
        verified=True,
        verified_by="dilshan",
        verification_date=date(2026, 2, 1),
    )
    assert updated.verified and store.get("c2_phishing_000001").verified_by == "dilshan"

    # an invalid update is rejected and leaves the row unchanged
    with pytest.raises(ValidationError):
        store.update("c2_benign_000001", language="fr")
    assert store.get("c2_benign_000001").language == "en"

    assert list(store.filter(label="phishing")["sample_id"]) == ["c2_phishing_000001"]
    assert list(store.filter(verified=False)["sample_id"]) == ["c2_benign_000001"]
    assert store.filter(label="benign", language="si").empty


def test_validate_all_clean_store_has_no_problems(store):
    store.add(write_sample(store, "phishing", 1, "<p>a</p>"))
    assert store.validate_all() == []


def test_validate_all_detects_missing_file_and_sha_mismatch(store):
    missing = write_sample(store, "phishing", 1, "<p>a</p>")
    changed = write_sample(store, "benign", 1, "<p>b</p>")
    store.add(missing)
    store.add(changed)

    (store.raw_dir / missing.file_path).unlink()
    (store.raw_dir / changed.file_path).write_text("<p>edited later</p>", encoding="utf-8")
    (store.raw_dir / "benign" / "stray.html").write_text("<p>?</p>", encoding="utf-8")

    problems = "\n".join(store.validate_all())
    assert "[c2_phishing_000001] file not found" in problems
    assert "[c2_benign_000001] sha256 mismatch" in problems
    assert "[unregistered] benign/stray.html" in problems


def test_validate_all_reports_invalid_rows(store):
    store.load()
    store.csv_path.write_text(
        store.csv_path.read_text(encoding="utf-8")
        + "c2_phishing_000001,phishing/x.html,phishing,xx,manual,https://a.b,2026-01-01,"
        + "a" * 64
        + ",,false,,,,\n",
        encoding="utf-8",
    )
    problems = MetadataStore(store.csv_path, store.raw_dir).validate_all()
    assert any("invalid language" in problem for problem in problems)


def test_sha256_helpers_agree(tmp_path):
    file = tmp_path / "f.bin"
    file.write_bytes(b"hello" * 1000)
    assert sha256_file(file) == sha256_bytes(b"hello" * 1000)


# ---- CLI end-to-end ------------------------------------------------------------


def run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run scripts/build_metadata.py as a real subprocess against tmp paths."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable,
        str(SCRIPT),
        "--metadata",
        str(tmp_path / "metadata.csv"),
        "--raw-dir",
        str(tmp_path / "raw"),
        *args,
    ]
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)


def test_cli_register_validate_show(tmp_path):
    register_args = [
        "register",
        "--file",
        str(FIXTURE_HTML),
        "--label",
        "benign",
        "--language",
        "en",
        "--source",
        "tranco",
        "--source-url",
        "https://bakery.example",
        "--date",
        "2026-03-01",
    ]
    result = run_cli(tmp_path, *register_args)
    assert result.returncode == 0, result.stderr
    assert "Registered c2_benign_000001" in result.stdout

    copied = tmp_path / "raw" / "benign" / "c2_benign_000001.html"
    assert copied.read_bytes() == FIXTURE_HTML.read_bytes()
    record = MetadataStore(tmp_path / "metadata.csv", tmp_path / "raw").get("c2_benign_000001")
    assert record.sha256 == sha256_file(FIXTURE_HTML)
    assert record.file_size_bytes == FIXTURE_HTML.stat().st_size
    assert record.collection_date == date(2026, 3, 1)

    # registering the same file again is an exact duplicate -> error, nothing copied
    again = run_cli(tmp_path, *register_args)
    assert again.returncode == 1 and "exact duplicate" in again.stderr
    assert not (tmp_path / "raw" / "benign" / "c2_benign_000002.html").exists()

    assert run_cli(tmp_path, "validate").returncode == 0

    shown = run_cli(tmp_path, "show", "--label", "benign")
    assert "c2_benign_000001" in shown.stdout
    assert "No matching records" in run_cli(tmp_path, "show", "--label", "phishing").stdout

    copied.write_text("tampered", encoding="utf-8")
    failed = run_cli(tmp_path, "validate")
    assert failed.returncode == 1 and "sha256 mismatch" in failed.stdout


def test_cli_rejects_unknown_label(tmp_path):
    result = run_cli(
        tmp_path, "register", "--file", str(FIXTURE_HTML), "--label", "spam",
        "--language", "en", "--source", "manual", "--source-url", "https://x.example",
    )  # fmt: skip
    assert result.returncode == 2 and "invalid choice" in result.stderr
