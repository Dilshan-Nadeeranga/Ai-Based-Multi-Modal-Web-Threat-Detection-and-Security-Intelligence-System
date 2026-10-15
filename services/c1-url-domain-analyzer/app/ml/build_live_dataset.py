"""Automated Live Threat Intelligence & Curated Benign Dataset Builder.

Constructs a balanced 200,000-sample real-world URL dataset by combining:
- URLhaus (abuse.ch) — Verified malware and payload URLs (Malicious: label=1)
- PhishTank — Active verified phishing campaigns (Malicious: label=1)
- Tranco Top 1M — High-reputation legitimate domains (Benign: label=0)
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from pathlib import Path
from typing import List, Set, Tuple

import pandas as pd

from app.ml.prepare_dataset import LargeDatasetPreparer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("build_live_dataset")


def build_live_dataset(
    target_malicious: int = 100000,
    target_benign: int = 100000,
    data_dir: Path = Path("data"),
) -> Path:
    raw_csv_path = data_dir / "raw_open_intel_200k.csv"
    cleaned_csv_path = data_dir / "dataset_200k.csv"

    urlhaus_zip = data_dir / "urlhaus_full.zip"
    phishtank_csv = data_dir / "phishtank.csv"
    tranco_zip = data_dir / "tranco_sample.zip"

    seen_malicious: Set[str] = set()
    malicious_rows: List[Tuple[str, int, str]] = []

    # 1. Ingest URLhaus
    if urlhaus_zip.exists():
        logger.info("Reading malicious URLs from URLhaus: %s", urlhaus_zip)
        with zipfile.ZipFile(urlhaus_zip) as zf:
            csv_name = zf.namelist()[0]
            with zf.open(csv_name) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore"))
                for row in reader:
                    if not row or row[0].startswith("#") or len(row) < 3:
                        continue
                    url = row[2].strip()
                    if url and url not in seen_malicious and len(url) >= 8:
                        seen_malicious.add(url)
                        malicious_rows.append((url, 1, "urlhaus"))
                        if len(malicious_rows) >= target_malicious:
                            break
        logger.info("Retrieved %d malicious URLs from URLhaus", len(malicious_rows))

    # 2. Ingest PhishTank to supplement up to target_malicious
    if phishtank_csv.exists() and len(malicious_rows) < target_malicious:
        needed = target_malicious - len(malicious_rows)
        logger.info("Reading up to %d more malicious URLs from PhishTank: %s", needed, phishtank_csv)
        with open(phishtank_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            url_idx = 1
            if header and "url" in header:
                url_idx = header.index("url")
            for row in reader:
                if not row or len(row) <= url_idx:
                    continue
                url = row[url_idx].strip()
                if url and url not in seen_malicious and len(url) >= 8:
                    seen_malicious.add(url)
                    malicious_rows.append((url, 1, "phishtank"))
                    if len(malicious_rows) >= target_malicious:
                        break
        logger.info("Total malicious URLs collected: %d", len(malicious_rows))

    # 3. Ingest Tranco Top 1M for Legitimate records with realistic multi-level web structure
    COMMON_BENIGN_PATHS = [
        "/",
        "",
        "/about",
        "/about-us",
        "/contact",
        "/contact-us",
        "/privacy",
        "/privacy-policy",
        "/terms",
        "/terms-of-service",
        "/help",
        "/support",
        "/faq",
        "/products",
        "/products/featured",
        "/products/category/all",
        "/products/apparel/activewear?category=mens&sort=popular&page=2",
        "/services",
        "/blog",
        "/blog/news/latest",
        "/blog/2026/updates",
        "/blog/2026/09/threat-intelligence-frameworks-and-indicators?utm_campaign=spring_promo",
        "/news",
        "/news/technology",
        "/news/2026/08/advancements-in-artificial-intelligence-and-cloud-infrastructure",
        "/docs",
        "/docs/guide/overview",
        "/docs/api/reference",
        "/docs/api/v2/endpoints/webhooks?version=latest&format=json",
        "/search",
        "/search?q=security",
        "/search?q=cybersecurity+research+papers+and+benchmarks&ref=hp_search",
        "/account",
        "/account/settings",
        "/features",
        "/pricing",
        "/download",
        "/login",
        "/signin",
        "/security",
        "/wiki/Technology",
        "/portal/dashboard",
        "/community/discussions",
        "/resources/whitepapers",
        "/company/careers",
        "/en/overview",
        "/en-us/products",
        "/en-us/windows",
        "/explore/topics/today",
        "/category/items?page=1",
        "/category/apparel/men?sort=newest&filter_color=black&page=3",
        "/articles/read?id=452",
        "/items/view?item_id=9847291&tracking_id=tr_8371920&source=direct",
        "/?utm_source=google&utm_medium=organic&utm_campaign=brand_search",
        "/?utm_source=newsletter&utm_medium=email&utm_campaign=weekly_digest_2026",
        "/?srsltid=AU7gw4Xh3ZyZaUEd7vknNJwSALGGys4-rUHXNgX9HwyRGK2QXX7UpLyN",
        "/?srsltid=AU7gw4VyCJedlpQaxcKzoDu14iOixOwPx6q4bKsOTgzlarQyW",
        "/?gclid=Cj0KCQjwlZixBhCoARIsADSpUTdY8xLqJv2uP7oMn3kZbR1mK",
        "/?fbclid=IwAR2yH8oM6zG9kL4vW1xQ3pT7sR5uN0mK8jV2cF",
        "/torvalds/linux",
        "/torvalds/linux/commits/master",
        "/gp/help/customer/display.html",
        "/3/library/urllib.parse.html",
        "/learning/security/threats/",
        "/questions/tagged/python",
        "/security-center/overview/",
        "/t5/Security/bd-p/Security",
        "/en-us/HT204144",
        "/wiki/Domain_Name_System",
    ]

    COMMON_PREFIXES = [
        "", "", "www.", "www.", "en.", "docs.", "support.", "api.", "m.", "blog.",
        "store.", "news.", "app.", "mail.", "help.", "community.", "portal.", "developer.",
    ]

    benign_rows: List[Tuple[str, int, str]] = []
    if tranco_zip.exists():
        logger.info("Reading legitimate domains from Tranco Top 1M: %s", tranco_zip)
        with zipfile.ZipFile(tranco_zip) as zf:
            csv_name = zf.namelist()[0]
            with zf.open(csv_name) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore"))
                for row in reader:
                    if not row or len(row) < 2:
                        continue
                    domain = row[1].strip().lower()
                    if domain and "." in domain:
                        idx = len(benign_rows)
                        path_suffix = COMMON_BENIGN_PATHS[idx % len(COMMON_BENIGN_PATHS)]
                        scheme = "https://" if (idx % 8) != 0 else "http://"
                        prefix = COMMON_PREFIXES[idx % len(COMMON_PREFIXES)]
                        url = f"{scheme}{prefix}{domain}{path_suffix}"
                        benign_rows.append((url, 0, "tranco_top1m"))
                        if len(benign_rows) >= target_benign:
                            break
        logger.info("Retrieved %d benign URLs from Tranco", len(benign_rows))

    total_collected = len(malicious_rows) + len(benign_rows)
    logger.info("Total raw records assembled: %d (%d malicious, %d benign)",
                total_collected, len(malicious_rows), len(benign_rows))

    # 4. Shuffle and save to intermediate raw CSV
    import random
    all_rows = malicious_rows + benign_rows
    rng = random.Random(42)
    rng.shuffle(all_rows)
    df_raw = pd.DataFrame(all_rows, columns=["url", "label", "source"])
    df_raw.to_csv(raw_csv_path, index=False)
    logger.info("Saved raw dataset to: %s (%d rows)", raw_csv_path, len(df_raw))

    # 5. Clean, standardize, and extract domains via LargeDatasetPreparer
    logger.info("Passing assembled records through LargeDatasetPreparer...")
    preparer = LargeDatasetPreparer()
    report = preparer.prepare_from_csv(
        input_csv=raw_csv_path,
        output_csv=cleaned_csv_path,
        chunk_size=50000,
        balance_classes=False,
    )
    logger.info("Cleaned dataset saved at: %s", cleaned_csv_path)
    logger.info("Dataset report: %s", report)
    return cleaned_csv_path


if __name__ == "__main__":
    build_live_dataset()
