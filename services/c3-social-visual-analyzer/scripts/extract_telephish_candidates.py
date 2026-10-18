"""Find BRAND_IMPERSONATION, FINANCIAL_SCAM and MALWARE candidates in TelePhish (rule-based pre-labels).

TelePhish only labels messages "phishing" / "malicious" from VirusTotal URL flags. This script assigns the C3
categories with explicit, evidence-recorded rules, so every label can be reviewed:

  all                  English; not posted in an official project / exchange broadcast channel (OFFICIAL_GROUPS:
                       their own announcements, flagged because of their own links or shorteners)
  brand_impersonation  is_phishing; names a catalog brand; the flagged link is NOT on that brand's own domains
                       (platform links such as discord.gg invites are abuse of a platform, not impersonation);
                       and either the link domain imitates the brand (high) or a lure word appears next to the
                       brand name (medium)
  financial_scam       is_phishing; >= 2 investment / giveaway signals (USDT/BTC amounts, earn, profit, bonus,
                       deposit, airdrop, giveaway, ...); not already brand_impersonation
  malware              is_malicious and not is_phishing; the link path is an executable / archive (high) or the
                       text pushes a crack / keygen / mod APK / cheat or hack tool / stealer (medium)

Every row is label_status "provisional" with reviewed=false. Licence (academic use, no redistribution): message
text goes only to gitignored data/raw/telephish/; the tracked statistics file holds counts and sample ids only.

Writes:
  data/raw/telephish/telephish_candidates.jsonl   (gitignored; text_baseline_dataset-style rows + evidence)
  data/raw/telephish/telephish_review.csv         (gitignored; fill the "decision" column: yes / no / other)
  data/statistics/telephish_candidates.json       (tracked; counts, rules, sample ids)

Usage:
  python scripts/extract_telephish_candidates.py
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import _bootstrap
from import_telephish import EXCLUDED_LINK_DOMAINS, excluded_domain, flag, near_duplicate_key
from prepare_text_baseline import clean_text

from app.services.threat_classifier import RISKY_EXTENSIONS

ROOT = _bootstrap.SERVICE_ROOT
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
OUT_DIR = ROOT / "data" / "raw" / "telephish"
CANDIDATES = OUT_DIR / "telephish_candidates.jsonl"
REVIEW = OUT_DIR / "telephish_review.csv"
STATS = ROOT / "data" / "statistics" / "telephish_candidates.json"
DECISIONS = ROOT / "data" / "annotations" / "telephish_review_decisions.json"
SOURCE = "TelePhish (Erfan et al., PST 2025)"
MIN_CHARS = 30

# Domains a brand itself owns besides its official_domain: links there abuse the platform, not the brand.
OWNED_DOMAINS = {
    "discord": {"discord.gg", "discord.com", "discordapp.com", "discord.new"},
    "instagram": {"instagram.com", "instagr.am", "ig.me"},
    "google": {"google.com", "goo.gl", "g.co", "forms.gle", "youtube.com", "youtu.be", "googleusercontent.com", "gstatic.com"},
    "metamask": {"metamask.io", "metamask.app.link"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "messenger.com"},
    "whatsapp": {"whatsapp.com", "wa.me", "chat.whatsapp.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "sharepoint.com", "onedrive.live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amzn.to"},
    "telegram": {"t.me", "telegram.org", "telegram.me"},
}
# Official broadcast channels of a project / exchange: their posts are the brand's own announcements, flagged by
# VirusTotal because of the brand's own links or URL shorteners, so they cannot be impersonation or scam samples.
OFFICIAL_GROUPS = {
    "CheeleeCommunity_EN", "LBank_en", "binanceexchange", "BinanceTurkish", "ChainGPT", "BybitEnglish",
    "BitMartExchange", "officialstaynex", "White_Bit", "BingXOfficial", "BoinkersOfficial2", "ISPYN_official2",
    "AtheneNetwork_Official",
}
CASE_SENSITIVE = {"apple", "steam", "chase", "amazon", "orange", "square", "discord", "ups", "aruba", "bt"}
LURE_DISTANCE = 80
LURE = re.compile(r"\b(free|claim|gift|giveaway|verify|verif\w*|support|airdrop|log ?in|reward|nitro|official|"
                  r"unlock|recover|suspend\w*|limited|winner|bonus|connect (your )?wallet|validate|sync)\b", re.I)
FINANCE_SIGNALS = [re.compile(p, re.I) for p in (
    r"\b\d[\d,.]*\s?(usdt|usd|btc|eth|bnb|sol|trx)\b", r"\$\s?\d[\d,.]*", r"\bearn(ing|ings)?\b", r"\bprofits?\b",
    r"\binvest(ment|ing|or)?s?\b", r"\bdeposit\b", r"\bbonus(es)?\b", r"\bairdrops?\b", r"\bgiveaways?\b",
    r"\bwithdraw(al)?\b", r"\bincome\b", r"\bdouble\b", r"\bmining\b", r"\b(daily|guaranteed) (returns?|profit)\b",
    r"\bsign ?up\b", r"\bfree (usdt|crypto|tokens?|coins?)\b", r"\bjackpot\b", r"\bcasino\b", r"\bfree ?spins?\b",
)]
MALWARE_TEXT = re.compile(r"\b(crack(ed)? (version|software|apk|app)|keygen|mod apk|mod menu|cheat (engine|menu|tool)|"
                          r"hack(ing)? (tool|apk|app)|aimbot|injector|wallhack|stealer|rat builder|crypter|"
                          r"download (this|the) (apk|exe|file|tool)|install (this|the) (apk|exe))\b", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]+|\b[\w.-]+\.[a-z]{2,}/[^\s\"'<>]*", re.I)


def host_of(url: str | None) -> str:
    try:
        return (urlparse(url if url and "://" in url else f"http://{url or ''}").hostname or "").removeprefix("www.")
    except ValueError:
        return ""


def on_domain(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def load_brands() -> list[dict]:
    brands = []
    for row in (json.loads(l) for l in CATALOG.read_text(encoding="utf-8").splitlines() if l.strip()):
        if not row.get("official_domain"):
            continue
        names = {row["display_name"], *row.get("aliases", [])}
        if row["brand_id"] not in CASE_SENSITIVE:
            names.add(row["brand_id"])
        sensitive = row["brand_id"] in CASE_SENSITIVE
        patterns = [re.compile(rf"(?<![\w]){re.escape(n)}(?![\w])", 0 if sensitive or len(n) <= 3 else re.I)
                    for n in names if len(n) > 1]
        token = re.sub(r"[^a-z0-9]", "", row["brand_id"])
        brands.append({"brand_id": row["brand_id"], "name": row["display_name"], "patterns": patterns,
                       "token": token, "owned": {row["official_domain"], *OWNED_DOMAINS.get(row["brand_id"], set())}})
    return brands


def brand_evidence(text: str, link_host: str, brands: list[dict]) -> tuple[str, str, list[str]] | None:
    """(brand_id, confidence, evidence) for the strongest impersonation signal, or None."""
    best = None
    lures = [(m.start(), m.group(0)) for m in LURE.finditer(text)]
    for brand in brands:
        mentions = [m.start() for p in brand["patterns"] for m in p.finditer(text)]
        if not mentions:
            continue
        if not link_host or on_domain(link_host, brand["owned"]):
            continue
        evidence = [f"names {brand['name']}", f"flagged link {link_host} is not a {brand['name']} domain"]
        if len(brand["token"]) >= 4 and brand["token"] in re.sub(r"[^a-z0-9]", "", link_host):
            candidate = (brand["brand_id"], "high", evidence + [f"link domain imitates {brand['name']}"])
        else:
            near = next((word for pos, word in lures if any(abs(pos - m) <= LURE_DISTANCE for m in mentions)), None)
            if not near:
                continue
            candidate = (brand["brand_id"], "medium", evidence + [f'lure word "{near}" next to the brand name'])
        if best is None or (candidate[1] == "high" and best[1] != "high"):
            best = candidate
    return best


def finance_evidence(text: str) -> list[str]:
    return sorted({m.group(0).strip() for p in FINANCE_SIGNALS if (m := p.search(text))})


def malware_evidence(text: str, urls: list[str]) -> tuple[str, list[str]] | None:
    for url in urls:
        path = (urlparse(url if "://" in url else f"http://{url}").path or "").lower()
        ext = next((e for e in RISKY_EXTENSIONS if path.endswith(e)), None)
        if ext:
            return "high", [f"link points to a {ext} file ({host_of(url)})"]
    match = MALWARE_TEXT.search(text)
    if match:
        return "medium", [f'text pushes "{match.group(0)}"']
    return None


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telephish", type=Path, default=Path(r"D:\Reasearch\Datasets\TelePhish\TelePhish.csv"))
    args = parser.parse_args()
    if not args.telephish.is_file():
        raise SystemExit(f"Missing {args.telephish}")
    csv.field_size_limit(sys.maxsize)
    brands = load_brands()

    counts = Counter()
    seen: set[str] = set()
    found: dict[str, list[dict]] = defaultdict(list)
    with args.telephish.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            phishing, malicious = flag(row, "is_phishing"), flag(row, "is_malicious")
            if not (phishing or malicious) or row.get("message_language") != "en":
                continue
            counts["flagged_en"] += 1
            if row.get("group_id") in OFFICIAL_GROUPS:
                counts["excluded_official_channel"] += 1
                continue
            link = row.get("malicious_link") or ""
            if excluded_domain(link):
                counts["excluded_false_positive_domain"] += 1
                continue
            text = clean_text(row.get("message_content"))
            key = near_duplicate_key(text)
            if len(key) < MIN_CHARS or key in seen:
                counts["short_or_duplicate"] += 1
                continue
            seen.add(key)
            raw_text = row.get("message_content") or ""
            urls = [u for u in _URL.findall(raw_text)] + ([link] if link else [])
            category = confidence = brand_id = None
            evidence: list[str] = []
            if phishing:
                hit = brand_evidence(raw_text, host_of(link), brands)
                if hit:
                    category, (brand_id, confidence, evidence) = "brand_impersonation", hit
                else:
                    signals = finance_evidence(raw_text)
                    if len(signals) >= 2:
                        category, confidence = "financial_scam", "high" if len(signals) >= 3 else "medium"
                        evidence = [f"finance/giveaway signals: {', '.join(signals[:5])}"]
            elif malicious:
                hit = malware_evidence(raw_text, urls)
                if hit:
                    category, (confidence, evidence) = "malware", hit
            if not category:
                continue
            found[category].append({
                "sample_id": f"TP_{int(row['sample_ids']):06d}",
                "source_dataset": SOURCE,
                "platform": "telegram",
                "label": 1,
                "scam_type": category,
                "confidence": confidence,
                "brand_id": brand_id,
                "evidence": evidence,
                "label_status": "provisional",
                "reviewed": False,
                "label_basis": "rule-based pre-label on a VirusTotal-flagged message; needs human review",
                "group_category": row.get("category"),
                "text": text,
                "text_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "malicious_link": link or None,
            })

    review = json.loads(DECISIONS.read_text(encoding="utf-8")) if DECISIONS.is_file() else {}
    decisions = review.get("decisions", {})
    excluded_by_review = []
    reviewed: dict[str, list[dict]] = defaultdict(list)
    for category, items in found.items():
        for item in items:
            decision = decisions.get(item["sample_id"])
            if decision and decision["category"] == "uncertain":
                excluded_by_review.append(item["sample_id"])
                continue
            if decision:
                item = dict(item, scam_type=decision["category"], reviewed=True, reviewer=review.get("reviewer"),
                            review_reason=decision["reason"], brand_name=decision.get("brand"),
                            rule_category=category)
            reviewed[item["scam_type"]].append(item)
    found = reviewed

    now = datetime.now(timezone.utc).isoformat()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = [dict(item, created_at=now) for category in sorted(found) for item in found[category]]
    CANDIDATES.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    with REVIEW.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sample_id", "category", "rule_confidence", "brand", "evidence", "pre_review_reason",
                         "text_preview", "flagged_link", "your decision (yes/no/other category)"])
        for r in rows:
            writer.writerow([r["sample_id"], r["scam_type"], r["confidence"], r.get("brand_name") or r["brand_id"] or "",
                             " | ".join(r["evidence"]), r.get("review_reason") or "", r["text"][:300],
                             r["malicious_link"] or "", ""])

    summary = {
        "source": SOURCE, "source_url": "https://github.com/minaerfan/TelePhish",
        "licence": "academic research and education only; no redistribution (text kept in gitignored data/raw/)",
        "label_status": "provisional rule-based pre-labels; reviewed=false until confirmed in telephish_review.csv",
        "rules": {
            "brand_impersonation": "phishing; names a catalog brand; flagged link not on the brand's own domains; "
                                   "link imitates the brand (high) or lure word in text (medium)",
            "financial_scam": "phishing; >= 2 investment/giveaway signals (>= 3 = high); not brand_impersonation",
            "malware": "malicious and not phishing; executable/archive link (high) or download/crack/mod/cheat text (medium)",
            "excluded_false_positive_domains": sorted(EXCLUDED_LINK_DOMAINS),
            "excluded_official_channels": sorted(OFFICIAL_GROUPS),
        },
        "counts": {**dict(counts), "excluded_as_uncertain_by_review": len(excluded_by_review)},
        "review": {"decisions_file": str(DECISIONS.relative_to(ROOT)).replace("\\", "/"), "reviewer": review.get("reviewer"),
                   "excluded_uncertain": excluded_by_review},
        "candidates": {c: {"total": len(items), "reviewed": sum(1 for i in items if i.get("reviewed"))}
                       for c, items in sorted(found.items())},
        "brand_impersonation_by_brand": dict(Counter(i.get("brand_name") or i.get("brand_id")
                                                     for i in found.get("brand_impersonation", [])).most_common()),
        "sample_ids": {c: [i["sample_id"] for i in items] for c, items in sorted(found.items())},
        "outputs": {"candidates": str(CANDIDATES.relative_to(ROOT)).replace("\\", "/"),
                    "review_sheet": str(REVIEW.relative_to(ROOT)).replace("\\", "/")},
        "created_at": now,
    }
    STATS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("counts", "candidates", "brand_impersonation_by_brand")}, indent=2))
    print(f"Wrote {len(rows)} candidates -> {CANDIDATES}\nReview sheet -> {REVIEW}")


if __name__ == "__main__":
    main()
