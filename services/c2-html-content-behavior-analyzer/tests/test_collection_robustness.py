"""Tests for collection robustness on Windows (Part 1 Batch B fixes).

Why: the first real run crashed when Windows Defender quarantined a page and
when candidates.csv was open in Excel. These tests simulate both (no network,
no real antivirus) and check that one bad page never stops a run, that locked
CSVs are retried, that skip/fail reasons are counted, and that `repair`
fixes the inconsistencies a crash can leave behind.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

import c2_analyzer.dataset.collector as collector_module
import c2_analyzer.utils.io as io_module
from c2_analyzer.config import project_root
from c2_analyzer.dataset.candidates import Candidate, CandidateStore
from c2_analyzer.dataset.collection import (
    collect,
    is_antivirus_block,
    reason_breakdown,
    reason_code,
)
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.fetcher import FetchResult
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.repair import repair
from c2_analyzer.utils.io import REPLACE_RETRY_DELAYS, FileSaveError, atomic_write_csv

ROOT = project_root()


class FakeFetcher:
    """Returns a prepared FetchResult (or raises a prepared exception) per URL."""

    mode = "static"

    def __init__(self, responses: dict[str, FetchResult | BaseException]) -> None:
        self.responses = responses

    def fetch(self, url: str) -> FetchResult:
        response = self.responses[url]
        if isinstance(response, BaseException):
            raise response
        return response


def page(url: str, text: str) -> FetchResult:
    html = f"<html><body><h1>{text}</h1><p>{'please log in to continue ' * 5}</p></body></html>"
    return FetchResult(
        "ok", url, html=html, final_url=url, http_status=200, content_type="text/html"
    )


def make_stores(tmp_path: Path, urls: list[str]) -> tuple[CandidateStore, MetadataStore]:
    candidates = CandidateStore(tmp_path / "metadata" / "candidates.csv")
    metadata = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    candidates.add_many(
        Candidate(url=url, suggested_label="phishing", language_hint="en", source="manual")
        for url in urls
    )
    candidates.save()
    return candidates, metadata


def run(candidates, metadata, fetcher):
    return collect(candidates.next_pending(), fetcher, metadata, candidates, show_progress=False)


# ---- B: one bad candidate never stops the run --------------------------------------------------


def test_antivirus_removed_file_marks_candidate_failed_and_run_continues(tmp_path, monkeypatch):
    urls = ["https://bad.example/", "https://good.example/"]
    candidates, metadata = make_stores(tmp_path, urls)
    hashed: list[Path] = []
    real_sha256 = collector_module.sha256_file

    def quarantine_first_file(path):
        hashed.append(Path(path))
        if len(hashed) == 1:
            Path(path).unlink()  # what Defender does to a detected phishing page
        return real_sha256(path)

    monkeypatch.setattr(collector_module, "sha256_file", quarantine_first_file)
    fetcher = FakeFetcher({urls[0]: page(urls[0], "bad"), urls[1]: page(urls[1], "good")})
    summary = run(candidates, metadata, fetcher)

    assert summary.counts == {"saved": 1, "skipped": 0, "failed": 1, "duplicate": 0}
    assert summary.reasons == {"blocked_by_antivirus": 1}
    bad = CandidateStore(candidates.csv_path).get(urls[0])
    assert bad.status == "failed" and bad.last_error.startswith("blocked_by_antivirus: ")
    assert CandidateStore(candidates.csv_path).get(urls[1]).status == "fetched"

    # pages were written inside the project (data/tmp), never the system Temp folder,
    # and nothing is left behind there
    assert all(path.parent == tmp_path / "tmp" for path in hashed)
    assert list((tmp_path / "tmp").iterdir()) == []
    assert MetadataStore(metadata.csv_path, metadata.raw_dir).validate_all() == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OSError(22, "Invalid argument"), True),  # what the real run raised
        (FileNotFoundError(2, "No such file"), True),
        (PermissionError(13, "Permission denied"), False),
        (OSError(28, "No space left on device"), False),
    ],
)
def test_antivirus_detection(error, expected):
    assert is_antivirus_block(error) is expected


def test_antivirus_detection_winerror_225():
    error = OSError(0, "Operation did not complete successfully because the file contains a virus")
    error.winerror = 225  # set by Windows itself on a real system
    assert is_antivirus_block(error)


def test_unexpected_error_marks_failed_and_run_continues(tmp_path):
    urls = ["https://crash.example/", "https://disk.example/", "https://good.example/"]
    candidates, metadata = make_stores(tmp_path, urls)
    fetcher = FakeFetcher(
        {
            urls[0]: RuntimeError("something odd"),
            urls[1]: OSError(28, "No space left on device"),
            urls[2]: page(urls[2], "good"),
        }
    )
    summary = run(candidates, metadata, fetcher)

    assert summary.counts["failed"] == 2 and summary.counts["saved"] == 1
    assert candidates.get(urls[0]).last_error == "RuntimeError: something odd"
    assert candidates.get(urls[1]).last_error.startswith("OSError: ")
    assert candidates.get(urls[0]).attempts == 1  # it can be retried later


def test_ctrl_c_still_stops_the_run(tmp_path):
    urls = ["https://one.example/", "https://two.example/", "https://three.example/"]
    candidates, metadata = make_stores(tmp_path, urls)
    fetcher = FakeFetcher({urls[0]: page(urls[0], "one"), urls[1]: KeyboardInterrupt()})
    summary = run(candidates, metadata, fetcher)  # must not raise, must not continue

    assert summary.counts["saved"] == 1
    on_disk = CandidateStore(candidates.csv_path)
    assert on_disk.get(urls[0]).status == "fetched"
    assert [c.url for c in on_disk.next_pending()] == urls[1:]


def test_failed_copy_leaves_no_file_in_raw(tmp_path, monkeypatch):
    source = tmp_path / "page.html"
    source.write_text("<html>hello</html>", encoding="utf-8")
    store = MetadataStore(tmp_path / "metadata.csv", tmp_path / "raw")

    def broken_copy(src, dst):
        Path(dst).write_text("half", encoding="utf-8")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(collector_module.shutil, "copy2", broken_copy)
    with pytest.raises(OSError):
        register_file(store, source, "phishing", "en", "manual", "https://x.example/")
    assert list((tmp_path / "raw" / "phishing").iterdir()) == []
    assert store.df.empty


# ---- C: locked CSV (Excel / antivirus) -----------------------------------------------------------


def test_replace_retried_while_file_is_locked(tmp_path, monkeypatch):
    target = tmp_path / "candidates.csv"
    real_replace = os.replace
    calls, sleeps = [], []

    def locked_twice(source, destination):
        calls.append(source)
        if len(calls) <= 2:
            raise PermissionError(13, "Access is denied")
        real_replace(source, destination)

    monkeypatch.setattr(io_module.os, "replace", locked_twice)
    monkeypatch.setattr(io_module.time, "sleep", sleeps.append)
    atomic_write_csv(pd.DataFrame({"a": ["1"]}), target, ["a"])

    assert target.read_text(encoding="utf-8") == "a\n1\n"
    assert len(calls) == 3 and sleeps == list(REPLACE_RETRY_DELAYS[:2])
    assert list(tmp_path.glob("*.tmp")) == []


def test_replace_gives_clear_error_and_removes_temp_file(tmp_path, monkeypatch):
    target = tmp_path / "candidates.csv"
    target.write_text("a\nold\n", encoding="utf-8")

    def always_locked(source, destination):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(io_module.os, "replace", always_locked)
    monkeypatch.setattr(io_module.time, "sleep", lambda seconds: None)
    with pytest.raises(FileSaveError, match="Close it in Excel or any other program"):
        atomic_write_csv(pd.DataFrame({"a": ["new"]}), target, ["a"])

    assert target.read_text(encoding="utf-8") == "a\nold\n"  # old version kept
    assert list(tmp_path.glob("*.tmp")) == []
    assert 2.5 <= sum(REPLACE_RETRY_DELAYS) <= 3.5 and len(REPLACE_RETRY_DELAYS) == 9


# ---- D: reasons --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "code"),
    [
        ("not HTML (content-type: application/zip)", "non_html_content"),
        ("HTTP 404", "http_404"),
        ("timeout after 15s", "timeout"),
        ("ConnectError: [Errno 11001] getaddrinfo failed", "dns_error"),
        ("ReadError: [WinError 10054] connection forcibly closed", "connection_reset"),
        ("ConnectError: [WinError 10061] No connection could be made", "connection_refused"),
        ("ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "tls_error"),
        ("blocked_by_antivirus: [Errno 22] Invalid argument", "blocked_by_antivirus"),
        ("blocked non-public address 10.0.0.1", "blocked_host"),
        ("larger than 5242880 bytes", "too_large"),
        ("more than 5 redirects", "too_many_redirects"),
        ("RemoteProtocolError: Server disconnected", "remoteprotocolerror"),
        ("", "unknown"),
        ("something new", "other"),
    ],
)
def test_reason_code(error, code):
    assert reason_code(error) == code


def test_reason_breakdown_and_run_summary(tmp_path):
    urls = [f"https://site{i}.example/" for i in range(5)]
    candidates, metadata = make_stores(tmp_path, urls)
    fetcher = FakeFetcher(
        {
            urls[0]: FetchResult("skipped", urls[0], reason="not HTML (content-type: x/zip)"),
            urls[1]: FetchResult("skipped", urls[1], reason="not HTML (content-type: missing)"),
            urls[2]: FetchResult("failed", urls[2], reason="HTTP 404"),
            urls[3]: FetchResult("failed", urls[3], reason="timeout after 15s"),
            urls[4]: page(urls[4], "ok"),
        }
    )
    summary = run(candidates, metadata, fetcher)

    expected = {"non_html_content": 2, "http_404": 1, "timeout": 1}
    assert summary.reasons == expected
    df = candidates.df
    assert reason_breakdown(df[df["status"].isin(["failed", "skipped"])]) == expected


# ---- E: repair ---------------------------------------------------------------------------------


def broken_state(tmp_path: Path) -> tuple[CandidateStore, MetadataStore, dict]:
    """Recreate what crashes leave behind."""
    urls = {
        "lost": "https://lost.example/",  # marked fetched, but the row was never saved
        "unlinked": "https://unlinked.example/",  # row saved, candidate save failed
        "ok": "https://ok.example/",  # consistent
    }
    candidates, metadata = make_stores(tmp_path, list(urls.values()))
    for key in ("unlinked", "ok"):
        source = tmp_path / f"{key}.html"
        source.write_text(f"<html>{key}</html>", encoding="utf-8")
        record, _ = register_file(
            metadata, source, "phishing", "en", "manual", urls[key], fetch_mode="static"
        )
        if key == "ok":
            candidates.mark(urls[key], "fetched", sample_id=record.sample_id)
    candidates.mark(urls["lost"], "fetched", sample_id="c2_phishing_000099")
    metadata.save()
    candidates.save()

    (tmp_path / "tmp").mkdir()
    (tmp_path / "tmp" / "0123abcd.html").write_text("leftover page", encoding="utf-8")
    (tmp_path / "metadata" / "candidates.csv.x1y2z3.tmp").write_text("half", encoding="utf-8")
    orphan = tmp_path / "raw" / "phishing" / "c2_phishing_000050.html"
    orphan.write_text("<html>orphan</html>", encoding="utf-8")
    return candidates, metadata, urls


def reload(candidates, metadata):
    return CandidateStore(candidates.csv_path), MetadataStore(metadata.csv_path, metadata.raw_dir)


def test_repair_fixes_inconsistent_state(tmp_path):
    candidates, metadata, urls = broken_state(tmp_path)
    report = repair(*reload(candidates, metadata))

    assert report.reset_to_pending == [urls["lost"]]
    assert report.relinked == [(urls["unlinked"], "c2_phishing_000001")]
    assert sorted(p.name for p in report.temp_files) == [
        "0123abcd.html",
        "candidates.csv.x1y2z3.tmp",
    ]
    assert report.orphan_raw_files == ["phishing/c2_phishing_000050.html"]
    assert report.missing_raw_files == []

    fixed, _ = reload(candidates, metadata)
    lost = fixed.get(urls["lost"])
    assert (lost.status, lost.sample_id, lost.attempts) == ("pending", None, 1)
    unlinked = fixed.get(urls["unlinked"])
    assert (unlinked.status, unlinked.sample_id) == ("fetched", "c2_phishing_000001")
    assert fixed.get(urls["ok"]).status == "fetched"
    assert list((tmp_path / "tmp").iterdir()) == []
    assert (tmp_path / "raw" / "phishing" / "c2_phishing_000050.html").exists()  # never deleted

    again = repair(*reload(candidates, metadata))  # running twice changes nothing more
    assert again.reset_to_pending == [] and again.relinked == [] and again.temp_files == []


def test_repair_dry_run_changes_nothing(tmp_path):
    candidates, metadata, urls = broken_state(tmp_path)
    before = candidates.csv_path.read_bytes()
    report = repair(*reload(candidates, metadata), dry_run=True)

    assert report.reset_to_pending == [urls["lost"]] and len(report.temp_files) == 2
    assert candidates.csv_path.read_bytes() == before
    assert (tmp_path / "tmp" / "0123abcd.html").exists()


def test_repair_reports_missing_raw_file(tmp_path):
    candidates, metadata, _ = broken_state(tmp_path)
    (tmp_path / "raw" / "phishing" / "c2_phishing_000002.html").unlink()  # quarantined
    report = repair(*reload(candidates, metadata))
    assert report.missing_raw_files == ["c2_phishing_000002"]


# ---- CLI ---------------------------------------------------------------------------------------


def run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable,
        str(ROOT / "scripts" / "collect.py"),
        "--candidates", str(tmp_path / "metadata" / "candidates.csv"),
        "--metadata", str(tmp_path / "metadata" / "metadata.csv"),
        "--raw-dir", str(tmp_path / "raw"),
        *args,
    ]  # fmt: skip
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)


def test_cli_repair_and_failures(tmp_path):
    candidates, metadata, urls = broken_state(tmp_path)
    candidates.mark(urls["lost"], "failed", error="HTTP 404")
    candidates.save()

    failures = run_cli(tmp_path, "failures", "--label", "phishing")
    assert failures.returncode == 0, failures.stderr
    assert "http_404: 1" in failures.stdout and "lost.example" in failures.stdout

    dry = run_cli(tmp_path, "repair", "--dry-run")
    assert dry.returncode == 0, dry.stderr
    assert "Would link 1 candidate(s)" in dry.stdout and "Would remove 2" in dry.stdout

    fixed = run_cli(tmp_path, "repair")
    assert fixed.returncode == 0, fixed.stderr
    assert "Link 1 candidate(s)" in fixed.stdout
    assert "phishing/c2_phishing_000050.html" in fixed.stdout and "NOT deleted" in fixed.stdout
