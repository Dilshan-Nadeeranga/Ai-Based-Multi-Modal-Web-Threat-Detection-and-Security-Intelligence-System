"""scripts/convert_phish360.py on a tiny synthetic Parquet pair (example.* URLs only)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

pq = pytest.importorskip("pyarrow.parquet")
import pyarrow as pa  # noqa: E402

from tests.conftest import FIXTURES_DIR  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import convert_phish360  # noqa: E402
import import_evidence  # noqa: E402


def _row(folder: str, cls: str, brand: str, url: str, domain: str, text: str, lang: str = "English") -> dict:
    kind = "legitimate" if cls == "legit" else brand
    return {
        "dataset_name": "Phish360", "folder_name": folder, "Class": cls, "brand": brand, "URL": url + "\n",
        "Domain": domain, "image_path": f"Phish360\\trainval\\{folder}_{kind}\\SCREEN-SHOT\\screen_shoot.png",
        "trafilatura_text": text, "html_text_language": lang, "full_html": "<html>not exported</html>",
    }


@pytest.fixture
def parquet_dir(tmp_path: Path) -> Path:
    folder = tmp_path / "phish360"
    folder.mkdir()
    legit = [
        _row("L00001", "legit", "unknown", "https://docs.example.com/a", "docs-example", "Synthetic legit page one"),
        _row("L00002", "legit", "unknown", "https://docs.example.com/b", "docs-example", "Same domain twice"),
        _row("L00003", "legit", "unknown", "https://shop.example.org/", "shop-example", "Synthetic legit page two"),
        _row("L00004", "legit", "unknown", "https://fr.example.net/", "fr-example", "Page en francais", "French"),
        _row("L00005", "legit", "unknown", "not a url", "bad", "Bad URL row"),
        _row("L00006", "legit", "unknown", "https://empty.example.com/", "empty-example", "   "),
    ]
    phish = [
        _row("P10001", "phish", "examplebank", "https://examplebank-login.example.invalid/x", "eb-login",
             "Synthetic phishing login page"),
        _row("P10002", "phish", "phish", "https://generic.example.invalid/", "generic", "Generic phishing page"),
        _row("P10003", "phish", "examplepay", "https://pay.example.invalid/", "pay", "Synthetic phishing login page"),
    ]
    pq.write_table(pa.Table.from_pylist(legit), folder / "Phish360_legit.parquet")
    pq.write_table(pa.Table.from_pylist(phish), folder / "Phish360_phish.parquet")
    return folder


def test_eligible_filters_and_deduplicates(parquet_dir: Path) -> None:
    rows = convert_phish360._load_rows(parquet_dir / "Phish360_legit.parquet")
    kept = convert_phish360.eligible(rows, "English", 20000)
    assert [r["folder_name"] for r in kept] == ["L00001", "L00003"]
    assert kept[0]["URL"] == "https://docs.example.com/a"
    assert len(convert_phish360.eligible(rows, "any", 20000)) == 3

    phish = convert_phish360.eligible(convert_phish360._load_rows(parquet_dir / "Phish360_phish.parquet"), "any", 20000)
    assert [r["folder_name"] for r in phish] == ["P10001", "P10002"]


def test_convert_writes_folders_and_imports(parquet_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    assert convert_phish360.main([str(parquet_dir), str(out), "--per-class", "5"]) == 0
    assert sorted(p.name for p in (out / "legit").iterdir()) == ["P360_L00001", "P360_L00003"]
    assert sorted(p.name for p in (out / "scam").iterdir()) == ["P360_P10001", "P360_P10002"]

    info = (out / "scam/P360_P10001/post_info.txt").read_text(encoding="utf-8")
    assert "platform: website\n" in info and "is_scam: 1\n" in info and "claimed_brand: examplebank\n" in info
    assert "source_reference: P10001\n" in info
    assert "claimed_brand: \n" in (out / "scam/P360_P10002/post_info.txt").read_text(encoding="utf-8")
    assert not any(p.suffix == ".png" for p in (out / "scam/P360_P10001").iterdir())

    data_dir = tmp_path / "data"
    assert import_evidence.main([str(out), "--data-dir", str(data_dir)]) == 0
    records = [json.loads(line) for line in
               (data_dir / "annotations/dataset_metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 4
    scam = next(r for r in records if r["source"]["source_reference"] == "P10001")
    assert scam["source"]["collection_method"] == "public_dataset"
    assert scam["source"]["platform"] == "website"
    assert {k: scam["labels"][k] for k in ("is_scam", "scam_type", "label_status")} == {
        "is_scam": 1, "scam_type": "phishing", "label_status": "verified"}
    assert scam["labels"]["misinformation"]["label_status"] == "not_annotated"
    assert scam["destination"]["original_url"] == "https://examplebank-login.example.invalid/x"


def test_rerun_never_overwrites(parquet_dir: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "evidence"
    convert_phish360.main([str(parquet_dir), str(out)])
    (out / "legit/P360_L00001/caption.txt").write_text("edited by annotator", encoding="utf-8")
    capsys.readouterr()
    assert convert_phish360.main([str(parquet_dir), str(out)]) == 0
    assert "0 new folder(s)" in capsys.readouterr().out
    assert (out / "legit/P360_L00001/caption.txt").read_text(encoding="utf-8") == "edited by annotator"


def test_screenshots_copied_when_images_root_given(parquet_dir: Path, tmp_path: Path) -> None:
    images = tmp_path / "images"
    shot = images / "Phish360/trainval/P10001_examplebank/SCREEN-SHOT/screen_shoot.png"
    shot.parent.mkdir(parents=True)
    shutil.copy(FIXTURES_DIR / "sample_post_page2.png", shot)
    out = tmp_path / "evidence"
    assert convert_phish360.main([str(parquet_dir), str(out), "--images-root", str(images)]) == 0
    assert (out / "scam/P360_P10001/post1.png").is_file()


def test_rerun_adds_screenshot_to_existing_unimported_folder(parquet_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    convert_phish360.main([str(parquet_dir), str(out)])
    images = tmp_path / "images"
    for folder in ("P10001_examplebank", "P10002_phish"):
        shot = images / f"Phish360/trainval/{folder}/SCREEN-SHOT/screen_shoot.png"
        shot.parent.mkdir(parents=True)
        shutil.copy(FIXTURES_DIR / "sample_post_page2.png", shot)
    (out / "scam/P360_P10002/imported.txt").write_text("SVT_000001\n", encoding="utf-8")

    assert convert_phish360.main([str(parquet_dir), str(out), "--images-root", str(images)]) == 0
    assert (out / "scam/P360_P10001/post1.png").is_file()
    assert not (out / "scam/P360_P10002/post1.png").exists()


def test_missing_parquet_is_an_error(tmp_path: Path, capsys) -> None:
    assert convert_phish360.main([str(tmp_path), str(tmp_path / "out")]) == 2
    assert "not found" in capsys.readouterr().err
