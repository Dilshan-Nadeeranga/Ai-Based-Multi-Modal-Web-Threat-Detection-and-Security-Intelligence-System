"""scripts/import_evidence.py against an isolated evidence folder and data directory."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from tests.conftest import FIXTURES_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import import_evidence  # noqa: E402


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    for folder in ("legit/001", "legit/002", "scam/001", "scam/002"):
        (root / folder).mkdir(parents=True)
    return root


def _fill(folder: Path, info: str, caption: str | None, images: list[str]) -> None:
    (folder / "post_info.txt").write_text(info, encoding="utf-8")
    if caption is not None:
        (folder / "caption.txt").write_text(caption, encoding="utf-8")
    for index, name in enumerate(images, start=1):
        shutil.copy(FIXTURES_DIR / name, folder / f"post{index}{Path(name).suffix}")


LEGIT = "platform: facebook\nis_scam: 0\nscam_type: legitimate\nlabel_status: verified\n" \
        "urls: https://example.com\ncollection_method: synthetic_test\n"
SCAM = "# comment\nplatform: instagram\nis_scam: 1\nscam_type: phishing\nlabel_status: provisional\n" \
       "urls: https://example.invalid/a https://example.invalid/b\nclaimed_brand: ExampleBank\n" \
       "collection_method: synthetic_test\n"


def _run(evidence: Path, data_dir: Path, *extra: str) -> int:
    return import_evidence.main([str(evidence), "--data-dir", str(data_dir), "--allow-synthetic", *extra])


def _records(data_dir: Path) -> list[dict]:
    path = data_dir / "annotations" / "dataset_metadata.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def test_write_templates_creates_blank_files(evidence: Path) -> None:
    assert import_evidence.main([str(evidence), "--write-templates"]) == 0
    legit_info = (evidence / "legit/001/post_info.txt").read_text(encoding="utf-8")
    scam_info = (evidence / "scam/002/post_info.txt").read_text(encoding="utf-8")
    assert "\nis_scam: 0\n" in legit_info and "\nis_scam: 1\n" in scam_info
    assert (evidence / "scam/002/caption.txt").read_text(encoding="utf-8") == ""


def test_untouched_templates_are_skipped(evidence: Path, tmp_path: Path, capsys) -> None:
    import_evidence.main([str(evidence), "--write-templates"])
    assert _run(evidence, tmp_path / "data") == 0
    assert "0 imported, 0 already imported, 4 empty, 0 failed" in capsys.readouterr().out
    assert _records(tmp_path / "data") == []


def test_import_links_caption_images_and_urls(evidence: Path, tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _fill(evidence / "legit/001", LEGIT, "Example security information", ["sample_legitimate.jpg"])
    _fill(evidence / "scam/001", SCAM, "ඔබගේ ගිණුම අවහිර කර ඇත",
          ["sample_scam.jpg", "sample_post_page2.png", "sample_post_page3.webp"])

    assert _run(evidence, data_dir) == 0

    legit, scam = _records(data_dir)
    assert legit["labels"]["is_scam"] == 0
    assert legit["post"]["text"] == "Example security information"
    assert [u.rstrip("/") for u in legit["post"]["embedded_urls"]] == ["https://example.com"]
    assert scam["post"]["text"] == "ඔබගේ ගිණුම අවහිර කර ඇත"
    assert [Path(p).name for p in scam["post"]["images"]] == [
        f"{scam['sample_id']}_01.jpg", f"{scam['sample_id']}_02.png", f"{scam['sample_id']}_03.webp"]
    assert len(scam["post"]["embedded_urls"]) == 2
    assert scam["brand"]["claimed_brand"] == "ExampleBank"
    assert (evidence / "scam/001/imported.txt").read_text(encoding="utf-8").startswith(scam["sample_id"])


def test_second_run_does_not_duplicate(evidence: Path, tmp_path: Path, capsys) -> None:
    data_dir = tmp_path / "data"
    _fill(evidence / "legit/001", LEGIT, "Example", ["sample_legitimate.jpg"])
    assert _run(evidence, data_dir) == 0
    assert _run(evidence, data_dir) == 0
    assert len(_records(data_dir)) == 1
    assert "already imported" in capsys.readouterr().out


def test_dry_run_writes_nothing(evidence: Path, tmp_path: Path, capsys) -> None:
    data_dir = tmp_path / "data"
    _fill(evidence / "scam/001", SCAM, "Example", ["sample_scam.jpg"])
    assert _run(evidence, data_dir, "--dry-run") == 0
    assert "READY  scam/001" in capsys.readouterr().out
    assert _records(data_dir) == []
    assert not (evidence / "scam/001/imported.txt").exists()


@pytest.mark.parametrize(
    ("folder", "info", "message"),
    [
        ("legit/001", SCAM, "under legit/ but is_scam is not 0"),
        ("scam/001", LEGIT.replace("is_scam: 0", "is_scam: 1"), "Invalid label"),
        ("scam/001", SCAM + "colour: red\n", "unknown entry"),
        ("scam/001", SCAM.replace("is_scam: 1", "is_scam: yes"), "is_scam must be 0, 1 or empty"),
        ("scam/001", SCAM.replace("https://example.invalid/a", "not-a-url"), "Malformed embedded URL"),
    ],
)
def test_bad_folders_fail_without_writing(evidence: Path, tmp_path: Path, capsys, folder, info, message) -> None:
    data_dir = tmp_path / "data"
    _fill(evidence / folder, info, "Example", ["sample_scam.jpg"])
    assert _run(evidence, data_dir) == 1
    assert message in capsys.readouterr().err
    assert _records(data_dir) == []
    assert not (evidence / folder / "imported.txt").exists()


def test_failure_in_one_folder_does_not_block_others(evidence: Path, tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _fill(evidence / "legit/001", LEGIT, "Example", ["not_an_image.jpg"])
    _fill(evidence / "legit/002", LEGIT, "Example", ["sample_legitimate.jpg"])
    assert _run(evidence, data_dir) == 1
    assert len(_records(data_dir)) == 1
    assert not (evidence / "legit/001/imported.txt").exists()
    assert (evidence / "legit/002/imported.txt").exists()


def test_synthetic_refused_in_research_folder(evidence: Path, capsys) -> None:
    assert import_evidence.main([str(evidence), "--allow-synthetic"]) == 2
    assert "--allow-synthetic requires --data-dir" in capsys.readouterr().err
