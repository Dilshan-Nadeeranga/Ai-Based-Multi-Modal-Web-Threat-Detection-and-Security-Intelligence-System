"""The CLI scripts, run against an isolated data directory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tests.conftest import FIXTURES_DIR

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import add_sample  # noqa: E402
import generate_statistics  # noqa: E402
import validate_dataset  # noqa: E402


@pytest.fixture
def data_dir(tmp_path: Path) -> str:
    return str(tmp_path / "cli_data")


def _add(data_dir: str, *extra: str) -> int:
    return add_sample.main(["--data-dir", data_dir, "--allow-synthetic", "--collection-method", "synthetic_test", *extra])


def test_cli_end_to_end(data_dir: str, capsys) -> None:
    assert _add(
        data_dir, "--platform", "facebook", "--text", "Official security awareness post",
        "--image", str(FIXTURES_DIR / "sample_legitimate.jpg"), "--url", "https://example.com",
        "--is-scam", "0", "--scam-type", "legitimate", "--label-status", "verified",
    ) == 0
    assert _add(
        data_dir, "--platform", "facebook", "--text", "Verify your example account immediately",
        "--image", str(FIXTURES_DIR / "sample_scam.jpg"), str(FIXTURES_DIR / "sample_post_page2.png"),
        "--url", "https://example.invalid/login", "--url", "https://example.invalid/pay",
        "--is-scam", "1", "--scam-type", "brand_impersonation", "--label-status", "verified",
        "--claimed-brand", "ExampleBrand",
    ) == 0
    output = capsys.readouterr().out
    assert "Created SVT_000001" in output and "Created SVT_000002" in output

    assert validate_dataset.main(["--data-dir", data_dir]) == 0
    assert generate_statistics.main(["--data-dir", data_dir, "--include-synthetic"]) == 0
    stats = json.loads((Path(data_dir) / "statistics" / "dataset_statistics.json").read_text(encoding="utf-8"))
    assert stats["binary_labels"] == {"legitimate": 1, "scam": 1, "undecided": 0, "not_annotated": 0}
    assert stats["total_images"] == 3 and stats["total_embedded_urls"] == 3


def test_cli_rejects_invalid_label(data_dir: str, capsys) -> None:
    code = _add(data_dir, "--platform", "facebook", "--text", "x", "--is-scam", "0",
                "--scam-type", "phishing", "--label-status", "verified")
    assert code == 1
    assert "DATASET_VALIDATION_ERROR" in capsys.readouterr().err


def test_cli_refuses_synthetic_in_research_folder(capsys) -> None:
    code = add_sample.main(["--allow-synthetic", "--platform", "facebook", "--text", "x",
                            "--is-scam", "0", "--scam-type", "legitimate", "--label-status", "verified"])
    assert code == 2
    assert "--allow-synthetic requires --data-dir" in capsys.readouterr().err


def test_cli_text_file_utf8(data_dir: str, tmp_path: Path) -> None:
    text_file = tmp_path / "post.txt"
    text_file.write_text("ඔබගේ ගිණුම අවහිර කර ඇත", encoding="utf-8")
    assert _add(data_dir, "--platform", "facebook", "--text-file", str(text_file),
                "--is-scam", "1", "--scam-type", "phishing", "--label-status", "provisional") == 0
    record = json.loads((Path(data_dir) / "annotations" / "dataset_metadata.jsonl").read_text(encoding="utf-8"))
    assert record["post"]["text"] == "ඔබගේ ගිණුම අවහිර කර ඇත"


def test_validator_exit_code_on_errors(data_dir: str) -> None:
    annotations = Path(data_dir) / "annotations"
    annotations.mkdir(parents=True)
    (annotations / "dataset_metadata.jsonl").write_text("not json\n", encoding="utf-8")
    assert validate_dataset.main(["--data-dir", data_dir]) == 1
