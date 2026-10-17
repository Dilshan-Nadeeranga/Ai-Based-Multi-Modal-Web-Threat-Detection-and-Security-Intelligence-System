"""ThreatRadar feed importer (Part 1 collection): collect.py import --feed threatradar.

Fixtures in tests/fixtures/threatradar mimic ThreatRadar's three outputs:
scraped/urls_only.csv (Telegram), scraped/reddit_urls_only.csv (Reddit) and
filtered/filtered_domains_<date>.json (domain filter). No network.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from argparse import Namespace
from collections import Counter
from datetime import date
from pathlib import Path

import pandas as pd
import pytest

from c2_analyzer.config import load_yaml_config, project_root
from c2_analyzer.dataset.candidates import CandidateStore
from c2_analyzer.dataset.feeds import (
    SKIP_ALLOW_LISTED,
    SKIP_BEFORE_SINCE,
    SKIP_DUPLICATE,
    SKIP_NO_RULE,
    SKIP_OVER_LIMIT,
    SKIP_UNDATED,
    ThreatRadarRules,
    import_feed,
    import_threatradar,
    is_allow_listed,
)
from c2_analyzer.utils.script_detect import native_script_hint

ROOT = project_root()
TR_DIR = ROOT / "tests" / "fixtures" / "threatradar"


def by_url(result) -> dict:
    return {candidate.url: candidate for candidate in result.candidates}


def test_imports_all_three_formats_with_weak_labels():
    result = import_threatradar(TR_DIR)
    assert result.read == Counter(telegram=6, reddit=6, domain_filter=5)
    assert result.rejected == [] and result.missing_files == []
    assert Counter(c.suggested_label for c in result.candidates) == Counter(
        phishing=2, crypto_scam=3, fake_ecommerce=3, malware_delivery=2
    )
    assert result.filtered == Counter({SKIP_ALLOW_LISTED: 3, SKIP_NO_RULE: 3, SKIP_DUPLICATE: 1})
    assert all(c.suggested_label != "benign" for c in result.candidates)

    rows = by_url(result)
    # source mapping
    assert rows["https://usdt-double.example/join"].source == "social_media_report"
    assert rows["https://mega-sale.example/"].source == "social_media_report"
    assert rows["https://g00gle-login.example/"].source == "other"
    # rules: mimicry (ThreatRadar's reason and host look-alike), keywords per field
    assert rows["https://g00gle-login.example/"].suggested_label == "phishing"
    assert rows["https://paypal-verify.example/login"].suggested_label == "phishing"
    assert rows["https://apps-free.example/get"].suggested_label == "malware_delivery"
    assert rows["https://airdrop-claim.example/"].suggested_label == "crypto_scam"
    # a bare domain (domain filter, or an empty url cell) becomes https://<domain>/
    assert "https://freebies-shop.example/" in rows and "https://apk-update.example/" in rows


def test_notes_name_source_reason_and_post():
    rows = by_url(import_threatradar(TR_DIR))
    telegram = rows["https://usdt-double.example/join"].notes
    assert telegram.startswith("ThreatRadar telegram: crypto/investment keyword 'usdt' in url")
    assert "— check label" in telegram
    assert "channel @cryptosignals_lk message_id=101" in telegram
    assert "seen 2026-10-10" in telegram
    reddit = rows["https://apps-free.example/get"].notes
    assert "ThreatRadar reddit:" in reddit and "r/Scams post_id=abc3" in reddit
    domain = rows["https://g00gle-login.example/"].notes
    assert "ThreatRadar domain_filter: brand mimicry of 'google'" in domain
    assert "filtered_domains_2026-10-13.json" in domain


def test_language_hint_from_sinhala_or_tamil_script():
    rows = by_url(import_threatradar(TR_DIR))
    assert rows["https://lanka-gain.example/"].language_hint == "si"  # channel name
    assert rows["https://kadai.example/"].language_hint == "ta"  # post title
    assert rows["https://usdt-double.example/join"].language_hint == "unknown"


def test_native_script_hint():
    assert native_script_hint("ශ්‍රී ලංකා", None) == "si"
    assert native_script_hint("தள்ளுபடி", "sale") == "ta"
    assert native_script_hint("crypto", "") is None
    assert native_script_hint("ලංකා", "தமிழ் தமிழ்") == "ta"  # more Tamil letters


def test_subreddit_name_is_not_a_label_cue():
    # quiet-page.example is posted in r/CryptoScams; only url + title are matched.
    result = import_threatradar(TR_DIR, sources=["reddit"])
    assert "https://quiet-page.example/" not in by_url(result)


def test_since_filters_old_and_undated_rows(tmp_path):
    result = import_threatradar(TR_DIR, since=date(2026, 10, 5))
    assert result.filtered[SKIP_BEFORE_SINCE] == 1
    assert "https://freebies-shop.example/" not in by_url(result)
    assert len(result.candidates) == 9

    undated = tmp_path / "scraped"
    undated.mkdir()
    (undated / "urls_only.csv").write_text(
        "domain,url,channel,date,message_id,views,has_photo\n"
        "x-shop.example,https://x-shop.example/,c,,1,0,False\n",
        encoding="utf-8",
    )
    assert import_threatradar(tmp_path).candidates  # no --since: kept
    assert import_threatradar(tmp_path, since=date(2026, 1, 1)).filtered[SKIP_UNDATED] == 1


def test_sources_subset_and_limit():
    only_df = import_threatradar(TR_DIR, sources=["domain_filter"])
    assert set(only_df.read) == {"domain_filter"} and len(only_df.candidates) == 3

    limited = import_threatradar(TR_DIR, limit=2)
    assert len(limited.candidates) == 2
    assert limited.filtered[SKIP_OVER_LIMIT] == 8
    with pytest.raises(ValueError, match="unknown ThreatRadar source"):
        import_threatradar(TR_DIR, sources=["facebook"])


def test_dedupe_against_known_urls_normalized():
    known = ["HTTPS://usdt-double.example/join/", "https://kadai.example"]
    result = import_threatradar(TR_DIR, known_urls=known)
    urls = by_url(result)
    assert "https://usdt-double.example/join" not in urls and "https://kadai.example/" not in urls
    assert result.filtered[SKIP_DUPLICATE] == 3  # 2 known + the Reddit repeat


def test_missing_files_are_reported_not_fatal(tmp_path):
    result = import_threatradar(tmp_path)
    assert result.candidates == [] and sum(result.read.values()) == 0
    assert len(result.missing_files) == 3
    with pytest.raises(FileNotFoundError, match="ThreatRadar data folder not found"):
        import_threatradar(tmp_path / "nope")


def test_broken_json_is_rejected_other_files_still_read(tmp_path):
    shutil.copytree(TR_DIR, tmp_path, dirs_exist_ok=True)
    (tmp_path / "filtered" / "filtered_domains_2026-10-14.json").write_text("{ not json")
    result = import_threatradar(tmp_path)
    assert any("filtered_domains_2026-10-14.json: unreadable" in r for r in result.rejected)
    assert result.read["domain_filter"] == 5 and len(result.candidates) == 10


def test_allow_list_covers_subdomains_not_free_hosts():
    allow = ("google.com", "github.com", "gov.lk")
    assert is_allow_listed("https://accounts.google.com/x", allow)
    assert is_allow_listed("https://www.health.gov.lk/", allow)
    assert not is_allow_listed("https://evil.github.io/", allow)
    assert not is_allow_listed("https://notgoogle.com/", allow)


def test_rules_come_from_config_and_are_validated():
    data = load_yaml_config("threatradar_rules")
    data["rules"] = [{"label": "fake_ecommerce", "name": "custom", "keywords": ["usdt"]}]
    custom = import_threatradar(TR_DIR, rules=ThreatRadarRules.from_dict(data))
    assert by_url(custom)["https://usdt-double.example/join"].suggested_label == "fake_ecommerce"

    for broken in (
        {"rules": [{"label": "benign", "name": "x", "keywords": ["a"]}]},
        {"sources": {"facebook": {"files": [], "source": "other", "match_fields": []}}},
        {"sources": {"telegram": {"files": [], "source": "nope", "match_fields": []}}},
    ):
        with pytest.raises(ValueError, match="threatradar_rules"):
            ThreatRadarRules.from_dict({**load_yaml_config("threatradar_rules"), **broken})


def test_import_feed_dispatches_a_folder():
    assert len(import_feed("threatradar", TR_DIR).candidates) == 10


# ---- CLI ---------------------------------------------------------------------------------------


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


def test_cli_import_summary_and_rerun_is_all_duplicates(tmp_path):
    first = run_cli(tmp_path, "import", "--feed", "threatradar", "--dir", str(TR_DIR))
    assert first.returncode == 0, first.stderr
    out = first.stdout
    assert "Rows read: telegram 6, reddit 6, domain_filter 5" in out
    assert "Imported 10 new candidate(s)" in out
    assert "  phishing: 2" in out and "  crypto_scam: 3" in out
    assert "  duplicate: 1" in out and "  allow-listed: 3" in out
    assert "  no rule matched: 3" in out

    queued = pd.read_csv(tmp_path / "candidates.csv", dtype=str)
    assert len(queued) == 10 and set(queued["status"]) == {"pending"}
    assert queued["notes"].str.contains("check label").all()

    again = run_cli(
        tmp_path, "import", "--feed", "threatradar", "--dir", str(TR_DIR),
        "--sources", "telegram,reddit", "--since", "2026-10-01", "--limit", "5",
    )  # fmt: skip
    assert again.returncode == 0, again.stderr
    assert "Imported 0 new candidate(s)" in again.stdout
    assert "Rows read: telegram 6, reddit 6" in again.stdout


def test_cli_argument_errors(tmp_path):
    no_dir = run_cli(tmp_path, "import", "--feed", "threatradar")
    assert no_dir.returncode == 1 and "--dir is required" in no_dir.stderr
    no_file = run_cli(tmp_path, "import", "--feed", "openphish")
    assert no_file.returncode == 1 and "--file is required" in no_file.stderr
    wrong = run_cli(
        tmp_path, "import", "--feed", "openphish", "--file", "x.txt", "--dir", str(TR_DIR)
    )
    assert wrong.returncode == 1 and "only for --feed threatradar" in wrong.stderr
    bad_day = run_cli(tmp_path, "import", "--feed", "threatradar", "--dir", ".", "--since", "x")
    assert bad_day.returncode == 2 and "YYYY-MM-DD" in bad_day.stderr
    bad_src = run_cli(tmp_path, "import", "--feed", "threatradar", "--dir", ".", "--sources", "fb")
    assert bad_src.returncode == 2 and "unknown source" in bad_src.stderr


def test_cli_dedupes_against_metadata_urls(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("collect_cli", ROOT / "scripts" / "collect.py")
    collect_cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collect_cli)

    class FakeMetadata:  # only .df is read
        df = pd.DataFrame(
            {"source_url": ["https://mega-sale.example"], "final_url": ["https://kadai.example/"]}
        )

    candidates = CandidateStore(tmp_path / "candidates.csv")
    args = Namespace(dir=TR_DIR, since=None, sources=("reddit",), limit=None)
    assert collect_cli.cmd_import_threatradar(args, candidates, FakeMetadata()) == 0
    urls = set(candidates.df["url"])
    assert urls == {"https://apps-free.example/get", "https://USDT-double.example/join/"}
    assert "  duplicate: 2" in capsys.readouterr().out
