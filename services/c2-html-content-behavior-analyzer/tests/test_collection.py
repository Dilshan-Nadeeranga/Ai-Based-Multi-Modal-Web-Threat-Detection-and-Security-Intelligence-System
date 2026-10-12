"""Tests for Part 1 Batch B: feeds, candidates, fetcher, script detection, collection.

No real network: every HTTP request goes to httpx.MockTransport. All files are
written to pytest's tmp_path, so data/ is never touched.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from c2_analyzer.config import project_root
from c2_analyzer.dataset.candidates import Candidate, CandidateStore
from c2_analyzer.dataset.collection import build_notes, collect, progress_table
from c2_analyzer.dataset.feeds import import_feed, parse_tranco
from c2_analyzer.dataset.fetcher import (
    BlockedHostError,
    FetchResult,
    FetchSettings,
    RateLimiter,
    StaticFetcher,
    check_host_allowed,
    decode_html,
)
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.utils.script_detect import detect_html_language, detect_language
from c2_analyzer.utils.url import extract_domain, normalize_url

ROOT = project_root()
FEEDS = ROOT / "tests" / "fixtures" / "feeds"
PAGES = ROOT / "tests" / "fixtures" / "sample_pages"
SINHALA = "ඔබගේ ගිණුම පැය 24ක් ඇතුළත අත්හිටුවනු ලැබේ. වහාම තහවුරු කරන්න."


# ---- helpers -------------------------------------------------------------------------


def make_fetcher(handler, **overrides) -> StaticFetcher:
    """StaticFetcher wired to a fake server (handler) and a limiter that never sleeps."""
    limiter = RateLimiter(1000, 0, clock=lambda: 0.0, sleep=lambda seconds: None)
    settings = FetchSettings.from_config(**overrides)
    return StaticFetcher(settings, transport=httpx.MockTransport(handler), limiter=limiter)


def html_response(body: str | bytes, content_type: str = "text/html; charset=utf-8", status=200):
    content = body.encode("utf-8") if isinstance(body, str) else body
    return httpx.Response(status, headers={"content-type": content_type}, content=content)


# ---- URL helpers -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, expected",
    [
        ("HTTPS://Example.COM/Login/", "https://example.com/Login"),
        ("https://example.com/a#section", "https://example.com/a"),
        ("example.com", "http://example.com"),
        ("https://example.com/?q=1", "https://example.com?q=1"),
    ],
)
def test_normalize_url(url, expected):
    assert normalize_url(url) == expected


def test_extract_domain():
    assert extract_domain("https://WWW.Example.com:8080/x") == "example.com"
    assert extract_domain("not a url") is None


# ---- feed importers ----------------------------------------------------------------------


def test_openphish_import_and_url_dedupe(tmp_path):
    result = import_feed("openphish", FEEDS / "openphish.txt")
    assert len(result.candidates) == 3
    assert all(
        c.suggested_label == "phishing" and c.source == "openphish" for c in result.candidates
    )
    assert len(result.rejected) == 1  # "not a url at all"

    store = CandidateStore(tmp_path / "candidates.csv")
    added, duplicates = store.add_many(result.candidates)
    # the 2nd URL differs only by host case, trailing "/" and #fragment
    assert (added, duplicates) == (2, 1)
    assert store.add_many(result.candidates) == (0, 3)  # importing again adds nothing


def test_phishtank_import():
    result = import_feed("phishtank", FEEDS / "phishtank.csv")
    assert [c.url for c in result.candidates] == [
        "https://appleid-unlock.example/verify",
        "http://office365-mail.example/owa",
    ]
    assert {c.source for c in result.candidates} == {"phishtank"}


def test_urlhaus_keeps_online_html_pages_only():
    result = import_feed("urlhaus", FEEDS / "urlhaus.csv")
    assert [c.url for c in result.candidates] == [
        "http://fake-update.example/chrome-update.html",
        "http://drive-by.example/download",
    ]
    assert all(c.suggested_label == "malware_delivery" for c in result.candidates)
    assert result.filtered == {"direct link to a binary file": 2, "not online": 1}
    assert "ClearFake" in result.candidates[0].notes


def test_tranco_top_n_and_sample():
    top = parse_tranco(FEEDS / "tranco.csv", top=3)
    assert [c.url for c in top.candidates] == [
        "https://google.com/",
        "https://microsoft.com/",
        "https://facebook.com/",
    ]
    assert all(c.suggested_label == "benign" for c in top.candidates)

    first = parse_tranco(FEEDS / "tranco.csv", top=6, sample=2, seed=1)
    again = parse_tranco(FEEDS / "tranco.csv", top=6, sample=2, seed=1)
    assert len(first.candidates) == 2
    assert [c.url for c in first.candidates] == [c.url for c in again.candidates]  # reproducible


def test_tranco_reads_zip(tmp_path):
    import zipfile

    archive = tmp_path / "top-1m.csv.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("top-1m.csv", "1,google.com\n2,example.org\n")
    assert len(import_feed("tranco", archive, top=10).candidates) == 2


def test_manual_import_defaults_and_rejects():
    result = import_feed("manual", FEEDS / "manual.csv")
    shop, crypto = result.candidates
    assert (shop.suggested_label, shop.language_hint, shop.source) == (
        "fake_ecommerce",
        "si",
        "social_media_report",
    )
    assert (crypto.language_hint, crypto.source) == ("unknown", "manual")  # empty -> defaults
    assert crypto.notes == "Guaranteed returns, Telegram"
    assert len(result.rejected) == 1 and "spam" in result.rejected[0]


def test_manual_template_is_importable(tmp_path):
    """The template only has comment rows, so it imports cleanly with 0 candidates."""
    result = import_feed("manual", ROOT / "data" / "metadata" / "manual_urls_template.csv")
    assert result.candidates == [] and result.rejected == []


def test_short_row_is_rejected_not_crashing(tmp_path):
    short = tmp_path / "manual.csv"
    short.write_text(
        "url,label,language_hint\nhttps://ok.example/,benign,en\nhttps://short.example/\n",
        encoding="utf-8",
    )
    result = import_feed("manual", short)
    assert len(result.candidates) == 1 and len(result.rejected) == 1


def test_missing_column_is_a_clear_error(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("link\nhttps://x.example\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing column"):
        import_feed("phishtank", bad)


# ---- candidate store -------------------------------------------------------------------


def test_candidate_store_pending_mark_and_save(tmp_path):
    store = CandidateStore(tmp_path / "candidates.csv")
    store.add_many(
        [
            Candidate(url="https://a.example/", suggested_label="phishing", source="openphish"),
            Candidate(url="https://b.example/", suggested_label="benign", source="tranco"),
            Candidate(url="https://c.example/", suggested_label="phishing", source="openphish"),
        ]
    )
    assert [c.url for c in store.next_pending(label="phishing", limit=1)] == ["https://a.example/"]

    store.mark("https://A.example", "failed", error="HTTP 500")  # normalized lookup
    store.save()

    reloaded = CandidateStore(tmp_path / "candidates.csv")
    failed = reloaded.get("https://a.example/")
    assert (failed.status, failed.attempts, failed.last_error) == ("failed", 1, "HTTP 500")
    assert [c.url for c in reloaded.retryable(max_attempts=3)] == ["https://a.example/"]
    assert reloaded.retryable(max_attempts=1) == []
    assert reloaded.status_counts().loc["phishing", "failed"] == 1
    assert [p.name for p in tmp_path.iterdir()] == ["candidates.csv"]  # atomic, no temp files


# ---- fetcher ---------------------------------------------------------------------------


def test_fetch_html_saved_with_fetch_info():
    fetcher = make_fetcher(lambda request: html_response(f"<p>{SINHALA}</p>"))
    result = fetcher.fetch("https://si.example/page")
    assert result.outcome == "ok"
    assert SINHALA in result.html
    assert (result.http_status, result.final_url) == (200, "https://si.example/page")
    assert result.content_type == "text/html; charset=utf-8"


def test_fetch_sends_browser_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return html_response("<p>hi</p>")

    make_fetcher(handler).fetch("https://h.example/")
    assert "Chrome/" in seen["user-agent"]
    assert seen["accept-language"] == "en,si;q=0.9,ta;q=0.8"


def test_non_html_is_skipped():
    fetcher = make_fetcher(lambda r: html_response(b"MZ\x90\x00", "application/octet-stream"))
    result = fetcher.fetch("https://files.example/setup")
    assert result.outcome == "skipped" and "not HTML" in result.reason


def test_http_error_status_is_failed():
    fetcher = make_fetcher(lambda r: html_response("<h1>Not found</h1>", status=404))
    result = fetcher.fetch("https://gone.example/")
    assert (result.outcome, result.reason, result.http_status) == ("failed", "HTTP 404", 404)


def test_oversized_body_is_aborted_while_streaming():
    chunks = [b"<p>" + b"x" * 60 for _ in range(10)]  # 630 bytes, no Content-Length
    fetcher = make_fetcher(
        lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=iter(chunks)),
        max_bytes=100,
    )
    result = fetcher.fetch("https://big.example/")
    assert result.outcome == "skipped" and "larger than 100 bytes" in result.reason


def test_oversized_content_length_rejected_up_front():
    fetcher = make_fetcher(lambda r: html_response("<p>" + "x" * 500 + "</p>"), max_bytes=100)
    assert fetcher.fetch("https://big.example/").outcome == "skipped"


def test_redirect_records_final_url():
    def handler(request):
        if request.url.path == "/old":
            return httpx.Response(302, headers={"location": "https://new.example/landing"})
        return html_response("<p>landed</p>")

    result = make_fetcher(handler).fetch("https://old.example/old")
    assert result.outcome == "ok"
    assert result.final_url == "https://new.example/landing"


def test_too_many_redirects_failed():
    loop = make_fetcher(lambda r: httpx.Response(302, headers={"location": str(r.url) + "x"}))
    result = loop.fetch("https://loop.example/a")
    assert result.outcome == "failed" and "redirects" in result.reason


def test_network_error_failed():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    result = make_fetcher(handler).fetch("https://down.example/")
    assert result.outcome == "failed" and "ConnectError" in result.reason


@pytest.mark.parametrize(
    "url", ["http://localhost/", "http://127.0.0.1/", "http://192.168.1.1/", "http://[::1]/"]
)
def test_local_network_urls_blocked(url):
    with pytest.raises(BlockedHostError):
        check_host_allowed(url)
    assert make_fetcher(lambda r: html_response("x")).fetch(url).outcome == "skipped"


def test_redirect_into_local_network_blocked():
    fetcher = make_fetcher(
        lambda r: httpx.Response(302, headers={"location": "http://10.0.0.1/admin"})
    )
    result = fetcher.fetch("https://evil.example/")
    assert result.outcome == "skipped" and "10.0.0.1" in result.reason


# ---- charset decoding ------------------------------------------------------------------------


def test_sinhala_utf8_from_header():
    text, encoding = decode_html(f"<p>{SINHALA}</p>".encode(), "text/html; charset=UTF-8")
    assert SINHALA in text and encoding == "utf-8"


def test_sinhala_utf8_declared_only_in_meta():
    body = f'<html><head><meta charset="utf-8"></head><body>{SINHALA}</body></html>'.encode()
    text, encoding = decode_html(body, "text/html")
    assert SINHALA in text and encoding == "utf-8"


def test_meta_charset_windows_1252():
    body = '<meta http-equiv="Content-Type" content="text/html; charset=windows-1252"><p>café</p>'
    text, encoding = decode_html(body.encode("cp1252"), "text/html")
    assert "café" in text and encoding == "cp1252"


def test_wrong_or_unknown_charset_falls_back_to_utf8():
    text, _ = decode_html("<p>ok ✓</p>".encode() + b"\xff", "text/html; charset=does-not-exist")
    assert text.startswith("<p>ok ✓</p>")  # bad byte replaced, no crash


def test_utf8_bom():
    text, encoding = decode_html(b"\xef\xbb\xbf<p>bom</p>")
    assert text == "<p>bom</p>" and encoding == "utf-8"


# ---- rate limiter -------------------------------------------------------------------------------


def test_rate_limiter_spaces_requests():
    now = [0.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(1.0, 5.0, clock=lambda: now[0], sleep=sleep)
    limiter.wait("a.example")  # first request: no wait
    limiter.wait("b.example")  # other host: 1 request/second
    limiter.wait("a.example")  # same host again: 5 s after the first
    assert slept == [1.0, 4.0]


# ---- script-based language hint -------------------------------------------------------------


@pytest.mark.parametrize(
    "page, expected",
    [
        ("benign_simple.html", "en"),
        ("sinhala_urgency.html", "si"),
        ("tamil_page.html", "ta"),
        ("mixed_page.html", "mixed"),
    ],
)
def test_script_detect_fixtures(page, expected):
    assert detect_html_language((PAGES / page).read_text(encoding="utf-8")) == expected


def test_script_detect_edge_cases():
    assert detect_language("Hi") == "unknown"  # too few letters
    # Sinhala page with an English menu is still Sinhala
    assert detect_language("Home About Contact Login " + SINHALA) == "si"
    # text inside <script> is not visible and is ignored
    assert detect_html_language(f"<script>var a='{SINHALA}'</script><p>{'word ' * 10}</p>") == "en"


# ---- notes / redirect flag -----------------------------------------------------------------------


def test_cross_domain_redirect_flagged_for_scam_labels_only():
    redirected = FetchResult("ok", "https://evil.example/", final_url="https://www.paypal.com/")
    scam = Candidate(url="https://evil.example/", suggested_label="phishing", source="openphish")
    benign = Candidate(url="https://evil.example/", suggested_label="benign", source="tranco")
    assert "redirected to paypal.com" in build_notes(scam, redirected)
    assert build_notes(benign, redirected) is None


# ---- end to end -------------------------------------------------------------------------------


def test_end_to_end_manual_import_then_fetch(tmp_path):
    manual = tmp_path / "manual.csv"
    manual.write_text(
        "url,label,language_hint,source,notes\n"
        "https://shop-lk.example/deals,fake_ecommerce,si,social_media_report,FB ad\n"
        "https://coin.example/,crypto_scam,unknown,manual,\n"
        "https://coin-mirror.example/,crypto_scam,unknown,manual,\n"
        "https://files.example/app,malware_delivery,en,manual,\n"
        "https://dead.example/,phishing,en,manual,\n",
        encoding="utf-8",
    )
    sinhala_page = (PAGES / "sinhala_urgency.html").read_text(encoding="utf-8")
    english_page = "<html><body><h1>Double your Bitcoin</h1><p>" + "invest now " * 10 + "</p>"

    def server(request):
        host = request.url.host
        if host == "shop-lk.example":
            return html_response(sinhala_page)
        if host in ("coin.example", "coin-mirror.example"):  # identical content
            return html_response(english_page)
        if host == "files.example":
            return html_response(b"PK\x03\x04", "application/zip")
        return html_response("<h1>404</h1>", status=404)

    candidates = CandidateStore(tmp_path / "candidates.csv")
    metadata = MetadataStore(tmp_path / "metadata.csv", tmp_path / "raw")
    candidates.add_many(import_feed("manual", manual).candidates)

    counts = collect(
        candidates.next_pending(), make_fetcher(server), metadata, candidates, show_progress=False
    )
    assert counts == {"saved": 2, "skipped": 1, "failed": 1, "duplicate": 1}

    shop = metadata.get("c2_fake_ecommerce_000001")
    assert (shop.label, shop.language, shop.fetch_mode) == ("fake_ecommerce", "si", "static")
    assert (shop.http_status, shop.source, shop.notes) == (200, "social_media_report", "FB ad")
    assert (tmp_path / "raw" / shop.file_path).read_text(encoding="utf-8") == sinhala_page

    coin = metadata.get("c2_crypto_scam_000001")
    assert coin.language == "en"  # hint was unknown -> script detection

    assert candidates.get("https://shop-lk.example/deals").status == "fetched"
    assert candidates.get("https://shop-lk.example/deals").sample_id == shop.sample_id
    mirror = candidates.get("https://coin-mirror.example/")
    assert (mirror.status, mirror.sample_id) == ("duplicate", "c2_crypto_scam_000001")
    assert candidates.get("https://files.example/app").status == "skipped"
    assert candidates.get("https://dead.example/").status == "failed"

    # everything was saved to disk and the dataset is consistent
    assert MetadataStore(metadata.csv_path, metadata.raw_dir).validate_all() == []
    assert len(CandidateStore(candidates.csv_path).next_pending()) == 0

    table = progress_table(metadata.df)
    assert table.loc["fake_ecommerce", "si"] == 1
    assert table.loc["phishing", "still needed"] == "50 more, 20 more si"


# ---- CLI (no network commands) ----------------------------------------------------------------


def run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable,
        str(ROOT / "scripts" / "collect.py"),
        "--candidates", str(tmp_path / "candidates.csv"),
        "--metadata", str(tmp_path / "metadata.csv"),
        "--raw-dir", str(tmp_path / "raw"),
        *args,
    ]  # fmt: skip
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)


def test_cli_import_progress_and_empty_fetch(tmp_path):
    imported = run_cli(
        tmp_path, "import", "--feed", "urlhaus", "--file", str(FEEDS / "urlhaus.csv")
    )
    assert imported.returncode == 0, imported.stderr
    assert "Imported 2 new candidate(s)" in imported.stdout
    assert "direct link to a binary file" in imported.stdout

    progress = run_cli(tmp_path, "progress")
    assert progress.returncode == 0, progress.stderr
    assert "still needed" in progress.stdout and "pending" in progress.stdout

    nothing = run_cli(tmp_path, "fetch", "--label", "benign")
    assert nothing.returncode == 0 and "Nothing to fetch" in nothing.stdout


def test_cli_missing_feed_file(tmp_path):
    result = run_cli(tmp_path, "import", "--feed", "openphish", "--file", "nope.txt")
    assert result.returncode == 1 and "not found" in result.stderr


# ---- rendered mode -----------------------------------------------------------------------------


def test_rendered_mode_without_playwright_gives_clear_error():
    try:
        import playwright  # noqa: F401
    except ImportError:
        from c2_analyzer.dataset.fetcher import RenderedFetcher

        with pytest.raises(RuntimeError, match="Playwright"):
            RenderedFetcher()
    else:
        pytest.skip("playwright is installed")


def test_rendered_mode_starts_browser():
    pytest.importorskip("playwright")
    from c2_analyzer.dataset.fetcher import RenderedFetcher

    with RenderedFetcher() as fetcher:
        assert fetcher.fetch("http://127.0.0.1/").outcome == "skipped"  # local host blocked
