"""Threat-category classification for the live social post analysis.

Hybrid by necessity: only legitimate / phishing / financial_scam / data_theft have labelled text samples
(DistilBERT category model), misinformation has the Fakeddit labels (separate binary model), and
brand_impersonation / malware / browser_abuse / other_scam have no labelled samples, so they are assigned
from pipeline evidence (brand-domain consistency, capture behaviour, URL file types, page and OCR text).
Every category score is evidence for an analyst, not a calibrated probability.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

CATEGORIES = ("LEGITIMATE", "PHISHING", "BRAND_IMPERSONATION", "FINANCIAL_SCAM", "DATA_THEFT", "MALWARE",
              "BROWSER_ABUSE", "MISINFORMATION", "OTHER_SCAM")
DISPLAY = {
    "LEGITIMATE": "Legitimate", "PHISHING": "Phishing", "BRAND_IMPERSONATION": "Brand impersonation",
    "FINANCIAL_SCAM": "Financial scam", "DATA_THEFT": "Data theft", "MALWARE": "Malware",
    "BROWSER_ABUSE": "Browser abuse", "MISINFORMATION": "Misinformation", "OTHER_SCAM": "Other scam",
}
SOURCE = {
    "LEGITIMATE": "model", "PHISHING": "model + rules", "FINANCIAL_SCAM": "model + rules", "DATA_THEFT": "model + rules",
    "MISINFORMATION": "model", "BRAND_IMPERSONATION": "rules", "MALWARE": "rules", "BROWSER_ABUSE": "rules",
    "OTHER_SCAM": "rules",
}
# Ties are broken towards the more specific / more harmful category.
PRIORITY = ("MALWARE", "BROWSER_ABUSE", "BRAND_IMPERSONATION", "DATA_THEFT", "PHISHING", "FINANCIAL_SCAM", "OTHER_SCAM")
DETECT_AT = 0.5
KEYWORD_STEP = 0.10
KEYWORD_CAP = 0.30
RULE_STRONG, RULE_MEDIUM, RULE_WEAK = 0.90, 0.70, 0.50

RISKY_EXTENSIONS = {".apk", ".xapk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar",
                    ".ps1", ".hta", ".dmg", ".pkg", ".iso", ".zip", ".rar", ".7z", ".lnk"}
_FILE_IN_TEXT = re.compile(r"\b[\w-]+\.(apk|xapk|exe|msi|scr|bat|vbs|jar|ps1|hta|dmg)\b", re.I)


def _rx(*patterns: str) -> list[re.Pattern[str]]:
    return [re.compile(p, re.I) for p in patterns]


KEYWORDS = {
    "PHISHING": _rx(r"verify (your )?(account|identity|login)", r"(account|card) (has been |is |will be )?(suspended|locked|disabled|limited)",
                    r"confirm (your )?(password|login|details)", r"unusual (sign[- ]?in|login|activity)",
                    r"(log ?in|sign ?in) (now|here|to (verify|confirm|restore))", r"update (your )?(billing|payment) (info|details|method)"),
    "FINANCIAL_SCAM": _rx(r"double your (money|investment|crypto|btc)", r"guaranteed (returns?|profit|income)",
                          r"(you('ve| have)? )?won (a|the)? ?(prize|lottery|jackpot|giveaway)", r"(pay|send) (a |the )?(small )?(fee|deposit) (to|for)",
                          r"(earn|make) \$?\d[\d,]* (per|a) (day|week|hour)", r"investment (plan|opportunity|scheme)",
                          r"work from home", r"(crypto|bitcoin|forex) (trading|signals?|investment)"),
    "DATA_THEFT": _rx(r"\b(cvv|cvc)\b", r"card number", r"\b(otp|one[- ]time (password|code))\b", r"\bpin (number|code)\b",
                      r"(nic|passport|national id|ssn|social security) (number|copy|details)", r"(send|share|upload) (your|a) (id|selfie|passport|nic)",
                      r"bank (account )?(login|credentials|details)"),
    "MALWARE": _rx(r"download (the |our |this )?(app|apk|file|update|installer)", r"install (the |this )?(apk|app from)",
                   r"(flash|chrome|browser|security) update (required|needed)", r"enable (macros|content)"),
    "BROWSER_ABUSE": _rx(r"(click|press|tap) ['\"]?allow['\"]?", r"allow notifications?", r"(your )?(computer|pc|device|phone|browser) (is|has been) (infected|locked|blocked|compromised)",
                         r"virus(es)? (detected|found)", r"\d+ viruses", r"call (microsoft|apple|windows|technical|tech) support",
                         r"(windows|microsoft) (defender|security) (alert|warning)", r"do not (close|restart) (this|your) (page|window|computer)",
                         r"confirm (that )?you('re| are) not a robot by clicking allow"),
}


_PROMOTIONAL = re.compile(
    r"\b(giveaway|win|winners?|prize|raffle|contest|offer|discount|sale|deals?|promo(tion)?|coupon|voucher|gift ?cards?|"
    r"cashback|free|sign ?up|register|order now|shop now|buy now|apply now|claim|reward|bonus|airdrop|"
    r"usdt|rs\.?\s?\d|lkr\s?\d)\b|[$€£]\s?\d", re.IGNORECASE)


def looks_promotional(text: str) -> bool:
    """Promotions, ads and offer/scam lures: outside the news-headline domain the misinformation model was trained on."""
    return bool(_PROMOTIONAL.search(text or ""))


def _hits(category: str, texts: list[tuple[str, str]]) -> list[str]:
    found = []
    for source, text in texts:
        for pattern in KEYWORDS[category]:
            match = pattern.search(text or "")
            if match:
                found.append(f'"{match.group(0)}" in {source}')
    return found


def _risky_extension(url: str | None) -> str | None:
    if not url:
        return None
    path = urlsplit(url).path.lower()
    return next((ext for ext in RISKY_EXTENSIONS if path.endswith(ext)), None)


def classify(*, category_probs: dict[str, float] | None, misinformation_prob: float | None, scam_probability: float | None,
             post_text: str, ocr_text: str, embedded_url: str | None, capture: dict | None, consistency: dict | None,
             risk: dict | None) -> dict:
    """Score every category, pick a primary one and list all categories at or above DETECT_AT."""
    capture = capture or {}
    consistency = consistency or {}
    risk = risk or {}
    page_text = " ".join(filter(None, [capture.get("page_title"), capture.get("page_text")]))
    texts = [("post text", post_text), ("image text (OCR)", ocr_text), ("webpage", page_text)]
    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {c: [] for c in CATEGORIES}

    # --- model categories (+ keyword support)
    probs = {k.upper(): v for k, v in (category_probs or {}).items()}
    for category in ("PHISHING", "FINANCIAL_SCAM", "DATA_THEFT"):
        base = probs.get(category, 0.0)
        hits = _hits(category, texts)
        if probs:
            evidence[category].append(f"text model {base * 100:.0f}%")
        evidence[category] += hits
        scores[category] = min(1.0, base + min(KEYWORD_CAP, KEYWORD_STEP * len(hits)))
    # data_theft has only 10 labelled samples; asking for two or more kinds of credentials is data theft by definition.
    distinct = {p.pattern for p in KEYWORDS["DATA_THEFT"] for _, t in texts if p.search(t or "")}
    if len(distinct) >= 2:
        scores["DATA_THEFT"] = max(scores["DATA_THEFT"], RULE_MEDIUM)
    if probs:
        scores["LEGITIMATE"] = probs.get("LEGITIMATE", 0.0)
        evidence["LEGITIMATE"].append(f"text model {scores['LEGITIMATE'] * 100:.0f}%")

    # --- brand impersonation (consistency evidence)
    mismatch = consistency.get("brand_identity_mismatch") or {}
    flags = {f["code"]: f for f in consistency.get("flags") or []}
    brand = 0.0
    if mismatch.get("detected"):
        brand = {"strong": RULE_STRONG, "moderate": RULE_MEDIUM, "weak": RULE_WEAK}.get(mismatch.get("strength"), RULE_WEAK)
        evidence["BRAND_IMPERSONATION"].append(f"{mismatch.get('strength')} brand identity mismatch")
    if "LOOKALIKE_DOMAIN" in flags:
        brand = max(brand, RULE_STRONG)
        evidence["BRAND_IMPERSONATION"].append(flags["LOOKALIKE_DOMAIN"]["detail"])
    if "BRAND_DOMAIN_MISMATCH" in flags:
        brand = max(brand, RULE_STRONG if flags["BRAND_DOMAIN_MISMATCH"]["severity"] == "high" else RULE_MEDIUM)
        evidence["BRAND_IMPERSONATION"].append(flags["BRAND_DOMAIN_MISMATCH"]["detail"])
    scores["BRAND_IMPERSONATION"] = brand

    # --- malware (capture behaviour, file types, text)
    malware = 0.0
    if capture.get("error_code") == "DOWNLOAD_BLOCKED":
        malware = RULE_STRONG
        evidence["MALWARE"].append("the link started a file download (blocked by the sandbox)")
    if capture.get("downloads"):
        malware = RULE_STRONG
        evidence["MALWARE"].append(f"the page tried to download {', '.join(capture['downloads'][:3])}")
    urls = [embedded_url, (capture.get("short_link") or {}).get("expanded_url"), capture.get("final_url"),
            *[hop.get("url") for hop in capture.get("redirect_chain") or []]]
    for url in dict.fromkeys(u for u in urls if u):
        ext = _risky_extension(url)
        if ext:
            malware = max(malware, RULE_STRONG if ext not in {".zip", ".rar", ".7z", ".iso"} else RULE_MEDIUM)
            evidence["MALWARE"].append(f"link points to a {ext} file")
    for source, text in texts[:2]:
        match = _FILE_IN_TEXT.search(text or "")
        if match:
            malware = max(malware, RULE_MEDIUM)
            evidence["MALWARE"].append(f'executable file "{match.group(0)}" mentioned in {source}')
    malware_hits = _hits("MALWARE", texts)
    evidence["MALWARE"] += malware_hits
    scores["MALWARE"] = min(1.0, max(malware, RULE_WEAK if malware_hits else 0.0) + (KEYWORD_STEP if malware and malware_hits else 0.0))

    # --- browser abuse (permission prompts, dialogs, pop-ups, fake alerts)
    abuse = 0.0
    if capture.get("notification_requests"):
        abuse = RULE_STRONG
        evidence["BROWSER_ABUSE"].append(f"the page requested notification permission {capture['notification_requests']}x")
    if capture.get("dialogs"):
        abuse = max(abuse, RULE_MEDIUM)
        evidence["BROWSER_ABUSE"].append(f"{len(capture['dialogs'])} JavaScript dialog(s): {capture['dialogs'][0]}")
    if (capture.get("popups_blocked") or 0) >= 2:
        abuse = max(abuse, RULE_MEDIUM)
        evidence["BROWSER_ABUSE"].append(f"{capture['popups_blocked']} pop-up windows opened")
    elif capture.get("popups_blocked"):
        abuse = max(abuse, RULE_WEAK - 0.1)
        evidence["BROWSER_ABUSE"].append("1 pop-up window opened")
    abuse_hits = _hits("BROWSER_ABUSE", texts)
    evidence["BROWSER_ABUSE"] += abuse_hits
    if abuse_hits:
        abuse = max(abuse, RULE_MEDIUM if len(abuse_hits) >= 2 else RULE_WEAK) + (KEYWORD_STEP if abuse >= RULE_MEDIUM else 0.0)
    scores["BROWSER_ABUSE"] = min(1.0, abuse)

    # --- misinformation (separate binary model, co-occurs with the others)
    if misinformation_prob is not None:
        scores["MISINFORMATION"] = misinformation_prob
        evidence["MISINFORMATION"].append(f"misinformation model {misinformation_prob * 100:.0f}%")

    # --- other scam: suspicious overall, but no specific scam category
    specific = max(scores.get(c, 0.0) for c in PRIORITY[:-1])
    level = risk.get("level", "LOW")
    other = 0.0
    if specific < DETECT_AT:
        if level in ("MEDIUM", "HIGH"):
            other = max(other, float(risk.get("score") or 0.0), DETECT_AT)
            evidence["OTHER_SCAM"].append(f"overall risk {level} with no specific scam category")
        if scam_probability is not None and scam_probability >= DETECT_AT:
            other = max(other, scam_probability)
            evidence["OTHER_SCAM"].append(f"binary scam model {scam_probability * 100:.0f}%")
    scores["OTHER_SCAM"] = other

    threats = [c for c in PRIORITY if scores.get(c, 0.0) >= DETECT_AT]
    rank = {c: i for i, c in enumerate(PRIORITY)}
    threats.sort(key=lambda c: (-round(scores[c], 2), rank[c]))
    misinfo = scores.get("MISINFORMATION", 0.0) >= DETECT_AT
    if threats:
        primary = threats[0]
    elif misinfo:
        primary = "MISINFORMATION"
    elif probs or post_text or ocr_text or capture:
        primary = "LEGITIMATE"
        scores["LEGITIMATE"] = scores.get("LEGITIMATE", 1.0 - max([specific, other], default=0.0))
    else:
        primary = None
    detected = threats + (["MISINFORMATION"] if misinfo else [])

    return {
        "primary": primary,
        "primary_label": DISPLAY.get(primary) if primary else None,
        "detected": [{"category": c, "label": DISPLAY[c], "score": round(scores[c], 4)} for c in detected],
        "categories": [{"category": c, "label": DISPLAY[c], "score": round(scores[c], 4) if c in scores else None,
                        "source": SOURCE[c], "detected": c in detected or c == primary, "evidence": evidence[c]}
                       for c in CATEGORIES],
        "threshold": DETECT_AT,
        "category_model_available": bool(probs),
        "misinformation_model_available": misinformation_prob is not None,
    }
