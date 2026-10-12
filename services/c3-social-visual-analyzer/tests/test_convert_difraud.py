"""scripts/convert_difraud.py on a tiny synthetic job_scams folder (example.* data only)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import convert_difraud  # noqa: E402
import import_evidence  # noqa: E402


def _write(path: Path, rows: list[object]) -> None:
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n", encoding="utf-8")


@pytest.fixture
def job_dir(tmp_path: Path) -> Path:
    folder = tmp_path / "job_scams"
    folder.mkdir()
    _write(folder / "train.jsonl", [
        {"text": "Genuine data analyst role at Example Ltd.", "label": 0},
        {"text": "Work from home, earn $5000 weekly. Apply: https://jobs.example.invalid/apply now. "
                 "Mail hr.team@example.com or call +1 (555) 010-9999.", "label": 1},
        {"text": "Duplicated genuine ad", "label": 0},
        {"text": "Duplicated genuine ad", "label": 0},
        {"text": "Same text, two labels", "label": 0},
        "not json",
        {"text": "   ", "label": 1},
        {"text": "Bad label", "label": 3},
        "",
    ])
    _write(folder / "validation.jsonl", [{"text": "Same text, two labels", "label": 1},
                                          {"text": "Typing job, pay a training fee first", "label": 1}])
    _write(folder / "test.jsonl", [{"text": "Nurse vacancy, shifts 2015-2018 experience", "label": 0}])
    return folder


def test_read_and_eligible(job_dir: Path) -> None:
    rows = convert_difraud.eligible(convert_difraud.read_rows(job_dir), 20000)
    assert [(r.split, r.line, r.label) for r in rows] == [
        ("train", 1, 0), ("train", 2, 1), ("train", 3, 0), ("validation", 2, 1), ("test", 1, 0)]


def test_redact_email_and_phone_only() -> None:
    text = "Mail a.b@example.com, call +94 77 123 4567 or 011-2345678. Salary 50000, years 2015-2018."
    assert convert_difraud.redact(text) == "Mail [EMAIL], call [PHONE] or [PHONE]. Salary 50000, years 2015-2018."


def test_convert_then_import(job_dir: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "evidence"
    assert convert_difraud.main([str(job_dir), str(out), "--per-class", "5"]) == 0
    printed = capsys.readouterr().out
    assert "legit: 3 eligible rows, 3 selected, 3 new folder(s), only 3 available" in printed
    assert "scam : 2 eligible rows, 2 selected, 2 new folder(s)" in printed

    scam = out / "difraud/scam/DFD_train_2"
    info = (scam / "post_info.txt").read_text(encoding="utf-8")
    assert "platform: website\n" in info and "scam_type: financial_scam\n" in info
    assert "urls: https://jobs.example.invalid/apply\n" in info
    assert "source_reference: job_scams/train.jsonl:2\n" in info
    caption = (scam / "caption.txt").read_text(encoding="utf-8")
    assert "[EMAIL]" in caption and "[PHONE]" in caption and "example.com" not in caption

    data_dir = tmp_path / "data"
    assert import_evidence.main([str(out / "difraud"), "--data-dir", str(data_dir)]) == 0
    records = [json.loads(line) for line in
               (data_dir / "annotations/dataset_metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 5
    fake = next(r for r in records if r["source"]["source_reference"] == "job_scams/train.jsonl:2")
    assert fake["source"]["source_dataset"] == "DIFrauD job_scams"
    assert {k: fake["labels"][k] for k in ("is_scam", "scam_type", "label_status")} == {
        "is_scam": 1, "scam_type": "financial_scam", "label_status": "verified"}
    assert fake["post"]["images"] == []


def test_rerun_never_overwrites(job_dir: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "evidence"
    convert_difraud.main([str(job_dir), str(out)])
    caption = out / "difraud/legit/DFD_train_1/caption.txt"
    caption.write_text("edited", encoding="utf-8")
    capsys.readouterr()
    assert convert_difraud.main([str(job_dir), str(out)]) == 0
    assert "0 new folder(s)" in capsys.readouterr().out
    assert caption.read_text(encoding="utf-8") == "edited"


def test_missing_files_is_an_error(tmp_path: Path, capsys) -> None:
    assert convert_difraud.main([str(tmp_path), str(tmp_path / "out")]) == 2
    assert "no train.jsonl" in capsys.readouterr().err
