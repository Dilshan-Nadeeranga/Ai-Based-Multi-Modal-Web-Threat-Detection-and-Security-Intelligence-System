"""scripts/convert_fakeddit.py on a synthetic TSV (no network: downloads are faked)."""

from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

import pytest

from tests.conftest import FIXTURES_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import convert_fakeddit  # noqa: E402
import generate_statistics  # noqa: E402
import import_evidence  # noqa: E402

COLUMNS = ["author", "clean_title", "created_utc", "domain", "hasImage", "id", "image_url",
           "linked_submission_id", "num_comments", "score", "subreddit", "title", "upvote_ratio",
           "2_way_label", "3_way_label", "6_way_label"]
SIX_TO_TWO_THREE = {"0": ("1", "0"), "1": ("0", "2"), "2": ("0", "2"), "3": ("0", "2"), "4": ("0", "2"),
                    "5": ("0", "1")}
ROWS_PER_LABEL = {"0": 8, "1": 3, "2": 3, "3": 3, "4": 3, "5": 3}
ALL_IDS = [f"p{six}x{n}" for six, count in ROWS_PER_LABEL.items() for n in range(count)]


def _write_tsv(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, delimiter="\t")
        writer.writeheader()
        for six, (two, three) in SIX_TO_TWO_THREE.items():
            for n in range(ROWS_PER_LABEL[six]):
                post_id = f"p{six}x{n}"
                writer.writerow({
                    "author": "someuser", "clean_title": f"title {post_id}", "created_utc": "1551641244.0",
                    "domain": "i.example.com", "hasImage": "True", "id": post_id,
                    "image_url": f"https://i.example.com/{post_id}.jpg", "subreddit": f"sub{six}",
                    "title": f"Synthetic title {post_id}", "2_way_label": two, "3_way_label": three,
                    "6_way_label": six,
                })
        writer.writerow({"id": "noimage", "title": "x", "image_url": "", "2_way_label": "1",
                         "3_way_label": "0", "6_way_label": "0"})
        writer.writerow({"id": "bad/id", "title": "x", "image_url": "https://i.example.com/a.jpg",
                         "2_way_label": "1", "3_way_label": "0", "6_way_label": "0"})


@pytest.fixture
def tsv_dir(tmp_path: Path) -> Path:
    folder = tmp_path / "fakeddit"
    folder.mkdir()
    _write_tsv(folder / "multimodal_train.tsv")
    return folder


def _images_dir(tmp_path: Path, ids: list[str]) -> Path:
    images = tmp_path / "images"
    images.mkdir()
    for post_id in ids:
        shutil.copy(FIXTURES_DIR / "sample_legitimate.jpg", images / f"{post_id}.jpg")
    return images


def test_read_rows_skips_unusable_rows(tsv_dir: Path) -> None:
    rows = list(convert_fakeddit.read_rows(tsv_dir / "multimodal_train.tsv"))
    assert len(rows) == len(ALL_IDS)
    assert {r.post_id for r in rows}.isdisjoint({"noimage", "bad/id"})
    real = next(r for r in rows if r.six_way == "0")
    assert real.is_fake == 0 and real.misinfo_type.value == "real"
    assert next(r for r in rows if r.six_way == "4").misinfo_type.value == "manipulated_content"


def test_convert_with_local_images_and_import(tsv_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    code = convert_fakeddit.main([str(tsv_dir), str(out), "--per-category", "1",
                                  "--images-dir", str(_images_dir(tmp_path, ALL_IDS))])
    assert code == 0
    assert len(list((out / "fakeddit/fake").iterdir())) == 5
    assert len(list((out / "fakeddit/real").iterdir())) == 5

    folder = next((out / "fakeddit/fake").iterdir())
    info = (folder / "post_info.txt").read_text(encoding="utf-8")
    assert "platform: reddit\n" in info and "label_status: not_annotated\n" in info
    assert "is_fake: 1\n" in info and "misinfo_label_status: provisional\n" in info
    assert "someuser" not in info and "someuser" not in (folder / "caption.txt").read_text(encoding="utf-8")
    assert (folder / "post1.jpg").is_file()

    data_dir = tmp_path / "data"
    assert import_evidence.main([str(out), "--data-dir", str(data_dir)]) == 0
    records = [json.loads(line) for line in
               (data_dir / "annotations/dataset_metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 10
    sample = records[0]
    assert sample["source"]["platform"] == "reddit"
    assert sample["labels"]["is_scam"] is None and sample["labels"]["label_status"] == "not_annotated"
    assert sample["labels"]["misinformation"]["label_status"] == "provisional"
    assert sample["labels"]["misinformation"]["source_label"].startswith("fakeddit_2way=")

    assert generate_statistics.main(["--data-dir", str(data_dir)]) == 0
    stats = json.loads((data_dir / "statistics/dataset_statistics.json").read_text(encoding="utf-8"))
    assert stats["misinformation_labels"] == {"real": 5, "fake": 5, "undecided": 0, "not_annotated": 0}
    assert stats["binary_labels"] == {"legitimate": 0, "scam": 0, "undecided": 0, "not_annotated": 10}
    assert set(stats["class_distribution"].values()) == {0}
    assert stats["misinformation_type_distribution"]["false_connection"] == 1


def test_download_skips_bad_images_and_fills_from_spares(tsv_dir: Path, tmp_path: Path, monkeypatch) -> None:
    good = (FIXTURES_DIR / "sample_scam.jpg").read_bytes()
    calls: list[str] = []

    def fake_fetch(url: str, max_bytes: int, timeout: float):
        calls.append(url)
        if url.endswith("x0.jpg"):
            return b"not an image", url
        if url.endswith("x1.jpg"):
            return good, "https://i.example.com/removed.png"
        return good, url

    monkeypatch.setattr(convert_fakeddit, "fetch_image", fake_fetch)
    out = tmp_path / "evidence"
    assert convert_fakeddit.main([str(tsv_dir), str(out), "--per-category", "1", "--download-images",
                                  "--delay", "0"]) == 0
    fake_folders = list((out / "fakeddit/fake").iterdir())
    assert len(fake_folders) == 5
    assert all(f.name.endswith("x2") for f in fake_folders)
    assert len(list((out / "fakeddit/real").iterdir())) == 5
    assert len(calls) <= len(ALL_IDS)


def test_rerun_keeps_existing_folders(tsv_dir: Path, tmp_path: Path, capsys) -> None:
    images = _images_dir(tmp_path, ALL_IDS)
    out = tmp_path / "evidence"
    convert_fakeddit.main([str(tsv_dir), str(out), "--per-category", "1", "--images-dir", str(images)])
    capsys.readouterr()
    assert convert_fakeddit.main([str(tsv_dir), str(out), "--per-category", "1", "--images-dir", str(images)]) == 0
    assert "0 new" in capsys.readouterr().out
    assert len(list((out / "fakeddit/fake").iterdir())) == 5


def test_missing_tsv_and_missing_image_source(tmp_path: Path, capsys) -> None:
    assert convert_fakeddit.main([str(tmp_path), str(tmp_path / "out"), "--download-images"]) == 2
    assert "not found" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        convert_fakeddit.main([str(tmp_path), str(tmp_path / "out")])
