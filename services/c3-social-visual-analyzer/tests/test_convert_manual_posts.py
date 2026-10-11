"""scripts/convert_manual_posts.py on synthetic hand-collected posts (example.* URLs only)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from tests.conftest import FIXTURES_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import convert_manual_posts  # noqa: E402
import import_evidence  # noqa: E402

SPONSORED = "\u034f".join("Sponsored") + "\u034f"
LEGIT_TEXT = (
    "Example Bank\n" + SPONSORED + "\n0\u034f\n \u00b7\n"
    "Win a phone \U0001f4f1\nFollow us and comment.\nT&C: www.example.com/promo-tnc.\n...\n"
)
SCAM_TEXT = "Claim your free phone!\nEnter your information now.\n\nhttps://prize.example.invalid/show.php?id=1\n"


def _post(root: Path, rel: str, text: str | None, image: str | None = "sample_scam.jpg") -> Path:
    folder = root / rel
    folder.mkdir(parents=True)
    if text is not None:
        (folder / "New Text Document.txt").write_text(text, encoding="utf-8")
    if image:
        shutil.copy(FIXTURES_DIR / image, folder / f"{rel.replace('/', '_')}_n{Path(image).suffix}")
    return folder


@pytest.fixture
def manual_dir(tmp_path: Path) -> Path:
    root = tmp_path / "Manual"
    _post(root, "facebook/legimate/01", LEGIT_TEXT, "sample_legitimate.jpg")
    _post(root, "facebook/legimate/02", "Example Shop\n8 October at 17:46 .\n\nBig sale today\n", None)
    _post(root, "facebook/scam/01", SCAM_TEXT)
    _post(root, "facebook/scam/02", SCAM_TEXT.replace("id=1", "id=2"))
    (root / "facebook/scam/03").mkdir()
    (root / "notaplatform/scam/01").mkdir(parents=True)
    return root


@pytest.mark.parametrize("stamp", ["8 October at 17:46 .", "3 July .", "16h.", "6 December 2025 \u00b7",
                                   "October 8, 2025 at 9:05", "Yesterday at 10:00", "2d"])
def test_timestamp_line_marks_page_name(stamp: str) -> None:
    parsed = convert_manual_posts.parse_post_text(f"Example Page\n{stamp}\n\nPost body\n")
    assert parsed.page_name == "Example Page"
    assert parsed.caption == "Post body"


def test_sponsored_marker_and_separators_removed() -> None:
    parsed = convert_manual_posts.parse_post_text(LEGIT_TEXT)
    assert parsed.page_name == "Example Bank"
    assert parsed.caption == ("Win a phone \U0001f4f1\nFollow us and comment.\nT&C: www.example.com/promo-tnc.")
    assert parsed.urls == ["https://www.example.com/promo-tnc"]


def test_text_without_header_is_all_caption() -> None:
    parsed = convert_manual_posts.parse_post_text(SCAM_TEXT)
    assert parsed.page_name is None
    assert parsed.caption.startswith("Claim your free phone!\n")
    assert parsed.urls == ["https://prize.example.invalid/show.php?id=1"]


def test_extract_urls_dedupes_and_skips_invalid() -> None:
    text = "See (https://a.example.com/x), https://a.example.com/x and http:// nothing www.example.org!"
    assert convert_manual_posts.extract_urls(text) == ["https://a.example.com/x", "https://www.example.org"]


def test_read_text_falls_back_to_cp1252(tmp_path: Path) -> None:
    path = tmp_path / "ansi.txt"
    path.write_bytes("Pr\u00e4mien".encode("cp1252"))
    assert convert_manual_posts.read_text(path) == "Pr\u00e4mien"


def test_convert_then_import(manual_dir: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "evidence"
    assert convert_manual_posts.main([str(manual_dir), str(out), "--scam-type", "data_theft"]) == 0
    printed = capsys.readouterr()
    assert "WARN   facebook/scam/02: same image as facebook/scam/01" in printed.out
    assert "EMPTY  facebook/scam/03" in printed.out
    assert "notaplatform/: not a platform" in printed.err
    assert "4 new, 0 already present, 1 empty, 0 failed" in printed.out

    legit = out / "manual/facebook/legit/facebook_legit_01"
    info = (legit / "post_info.txt").read_text(encoding="utf-8")
    assert "is_scam: 0\n" in info and "claimed_brand: Example Bank\n" in info
    assert "urls: https://www.example.com/promo-tnc\n" in info
    assert "source_reference: facebook/legimate/01\n" in info
    assert (legit / "post1.jpg").is_file()
    assert not (out / "manual/facebook/legit/facebook_legit_02/post1.jpg").exists()
    scam_info = (out / "manual/facebook/scam/facebook_scam_01/post_info.txt").read_text(encoding="utf-8")
    assert "scam_type: data_theft\n" in scam_info and "label_status: verified\n" in scam_info
    assert (manual_dir / "facebook/legimate/01/New Text Document.txt").read_text(encoding="utf-8") == LEGIT_TEXT

    data_dir = tmp_path / "data"
    assert import_evidence.main([str(out / "manual"), "--data-dir", str(data_dir)]) == 0
    records = [json.loads(line) for line in
               (data_dir / "annotations/dataset_metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 4
    first = next(r for r in records if r["source"]["source_reference"] == "facebook/legimate/01")
    assert first["source"]["platform"] == "facebook"
    assert first["source"]["collection_method"] == "manual"
    assert first["post"]["text"].startswith("Win a phone")
    assert first["labels"]["is_scam"] == 0


def test_default_scam_type_is_unknown_provisional(manual_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    assert convert_manual_posts.main([str(manual_dir), str(out)]) == 0
    info = (out / "manual/facebook/scam/facebook_scam_01/post_info.txt").read_text(encoding="utf-8")
    assert "scam_type: unknown\n" in info and "label_status: provisional\n" in info
    assert import_evidence.main([str(out / "manual"), "--dry-run", "--data-dir", str(tmp_path / "data")]) == 0


def test_rerun_keeps_edits_and_own_post_info_is_used(manual_dir: Path, tmp_path: Path, capsys) -> None:
    own = "platform: facebook\nis_scam: 1\nscam_type: financial_scam\nlabel_status: verified\n"
    (manual_dir / "facebook/scam/02/post_info.txt").write_text(own, encoding="utf-8")
    out = tmp_path / "evidence"
    convert_manual_posts.main([str(manual_dir), str(out)])
    assert (out / "manual/facebook/scam/facebook_scam_02/post_info.txt").read_text(encoding="utf-8") == own

    caption = out / "manual/facebook/scam/facebook_scam_01/caption.txt"
    caption.write_text("edited by annotator", encoding="utf-8")
    capsys.readouterr()
    assert convert_manual_posts.main([str(manual_dir), str(out)]) == 0
    assert "0 new, 4 already present" in capsys.readouterr().out
    assert caption.read_text(encoding="utf-8") == "edited by annotator"


def test_two_text_files_fail_the_post(manual_dir: Path, tmp_path: Path, capsys) -> None:
    (manual_dir / "facebook/scam/01/second.txt").write_text("extra", encoding="utf-8")
    assert convert_manual_posts.main([str(manual_dir), str(tmp_path / "evidence")]) == 1
    assert "FAIL   facebook/scam/01: more than one text file" in capsys.readouterr().err


def test_missing_manual_dir_is_an_error(tmp_path: Path, capsys) -> None:
    assert convert_manual_posts.main([str(tmp_path / "nope"), str(tmp_path / "out")]) == 2
    assert "not found" in capsys.readouterr().err
