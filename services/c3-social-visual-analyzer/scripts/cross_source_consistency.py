"""Cross-source consistency engine: compare post text, image, OCR, brand and destination.

For every sample in dataset_metadata.jsonl it gathers the evidence produced by
earlier steps and compares the sources pairwise:

  post text <-> post image          CLIP text-image cosine
  post text <-> OCR                 CLIP text-text cosine (semantic) + TF-IDF char n-gram cosine (lexical)
  text / OCR <-> detected brand     brand mentions vs logo/CLIP brand
  post brand <-> website brand      brand from post vs brand from destination screenshot/title/domain
  post image <-> website screenshot CLIP image cosine + pHash
  claimed brand <-> destination     official domain / lookalike / unverifiable

then raises consistency flags, a brand identity mismatch verdict and a short
evidence summary. Flags are evidence for analysts, NOT scam labels.

Inputs (from earlier scripts):
  data/annotations/dataset_metadata.jsonl, brand_catalog.jsonl, webpage_captures.jsonl,
  text_baseline_dataset.jsonl, clip_brand_predictions.jsonl, logo_similarity_results.jsonl,
  post_web_similarity.jsonl

Writes:
  data/annotations/consistency_results.jsonl
  data/annotations/consistency_checklist_status.json
  data/statistics/consistency_statistics.json
  data/processed/consistency/ocr_cache.json      (gitignored)

Usage:
  python scripts/cross_source_consistency.py
  python scripts/cross_source_consistency.py --no-ocr
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

import numpy as np
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer

from clip_brand_analysis import embed_images, embed_texts, letterbox, load_clip, open_rgb
from prepare_text_baseline import clean_text, compare as word_overlap

ROOT = _bootstrap.SERVICE_ROOT
ANNOTATIONS = ROOT / "data" / "annotations"
METADATA = ANNOTATIONS / "dataset_metadata.jsonl"
CATALOG = ANNOTATIONS / "brand_catalog.jsonl"
CAPTURES = ANNOTATIONS / "webpage_captures.jsonl"
TEXT_BASELINE = ANNOTATIONS / "text_baseline_dataset.jsonl"
CLIP_PREDICTIONS = ANNOTATIONS / "clip_brand_predictions.jsonl"
LOGO_RESULTS = ANNOTATIONS / "logo_similarity_results.jsonl"
POST_WEB = ANNOTATIONS / "post_web_similarity.jsonl"
RESULTS = ANNOTATIONS / "consistency_results.jsonl"
STATUS = ANNOTATIONS / "consistency_checklist_status.json"
STATISTICS = ROOT / "data" / "statistics" / "consistency_statistics.json"
OCR_CACHE = ROOT / "data" / "processed" / "consistency" / "ocr_cache.json"
DEFAULT_CLIP = "openai/clip-vit-base-patch16"

CHECKLIST = [
    "Compare post text ↔ post image",
    "Compare post text ↔ OCR",
    "Compare text ↔ detected brand",
    "Compare OCR ↔ detected brand",
    "Compare post brand ↔ website brand",
    "Compare post image ↔ website screenshot",
    "Compare claimed brand ↔ destination dom",
    "Calculate semantic similarity",
    "Calculate visual similarity",
    "Detect brand identity mismatch",
    "Generate consistency flags",
    "Produce evidence summary",
]

# Thresholds (documented in consistency_statistics.json).
TEXT_IMAGE_LOW = 0.18          # CLIP ViT-B/16 text-image cosine; matching pairs are typically 0.25-0.35
TEXT_OCR_SEMANTIC_LOW = 0.60   # CLIP text-text cosine
TEXT_OCR_LEXICAL_LOW = 0.10    # TF-IDF char 3-5 gram cosine
POST_WEB_VISUAL_LOW = 0.50     # CLIP image-image cosine
MIN_OCR_CHARS = 15

SHORTENERS = {"itl.ink", "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "lnkd.in", "fb.me", "tiny.cc", "rb.gy", "t.ly"}
GENERIC_NAME_TOKENS = {"bank", "the", "of", "and", "ltd", "plc", "inc", "incorporated", "sri", "lanka", "company",
                       "co", "limited", "group", "official", "pvt", "corporation", "corp", "middle", "east", "united"}
AMBIGUOUS_BRANDS = {"apple", "steam", "chase", "amazon", "match", "orange", "office", "square", "discord", "ups",
                    "aruba", "bt"}
SEVERITY = {"low": 1, "medium": 2, "high": 3}

_TLD = tldextract.TLDExtract(suffix_list_urls=())


def mark_checklist(item: str, done: bool = True) -> None:
    if STATUS.exists():
        data = json.loads(STATUS.read_text(encoding="utf-8"))
    else:
        data = {"task": "Cross-Source Consistency Engine",
                "items": [{"item": name, "done": False} for name in CHECKLIST]}
    for entry in data["items"]:
        if entry["item"] == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data["items"] if entry["done"])
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def registered_domain(url_or_host: str | None) -> str | None:
    if not url_or_host:
        return None
    parts = _TLD(url_or_host)
    return f"{parts.domain}.{parts.suffix}".lower() if parts.domain and parts.suffix else None


# ------------------------------------------------------------------ brands

class BrandIndex:
    def __init__(self, catalog: list[dict]) -> None:
        self.brands = {row["brand_id"]: row for row in catalog}
        self.official = {bid: registered_domain(row.get("official_domain")) for bid, row in self.brands.items()}
        self.domain_to_brand = {domain: bid for bid, domain in self.official.items() if domain}
        self.patterns: dict[str, list[re.Pattern]] = {}
        self.lookup: dict[str, str] = {}
        for bid, row in self.brands.items():
            names = {row["display_name"], *row.get("aliases", [])}
            flags = 0 if bid in AMBIGUOUS_BRANDS else re.IGNORECASE
            if bid not in AMBIGUOUS_BRANDS:
                names.add(bid)
            self.patterns[bid] = [re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])", flags) for name in names if len(name) > 1]
            if row.get("official_domain"):
                self.patterns[bid].append(re.compile(rf"\b{re.escape(row['official_domain'])}\b", re.IGNORECASE))
            for name in (*names, bid):
                self.lookup[key(name)] = bid
        self.lookup.update({"boa": "bankofamerica", "att": "att", "citi": "citibank", "office": "microsoft"})

    def display(self, bid: str | None) -> str | None:
        return self.brands[bid]["display_name"] if bid in self.brands else None

    def mentions(self, text: str) -> list[str]:
        """Catalog brands named in ``text``, ordered by first appearance."""
        found = {}
        for bid, pats in self.patterns.items():
            positions = [m.start() for p in pats if (m := p.search(text or ""))]
            if positions:
                found[bid] = min(positions)
        return sorted(found, key=found.get)

    def resolve(self, name: str | None) -> str | None:
        return self.lookup.get(key(name)) if name else None

    def domain_check(self, claimed: str, catalog_id: str | None, domain: str | None) -> dict:
        """official / lookalike / name_in_domain / mismatch / unverifiable."""
        if not domain:
            return {"status": "not_available"}
        label = domain.split(".")[0]
        if catalog_id:
            official = self.official.get(catalog_id)
            if official and domain == official:
                return {"status": "official", "official_domain": official}
            if key(catalog_id) in key(label) or key(self.brands[catalog_id]["display_name"]) in key(label):
                return {"status": "lookalike", "official_domain": official}
            return {"status": "mismatch", "official_domain": official}
        tokens = [t for t in re.findall(r"[a-z0-9]+", claimed.lower()) if len(t) >= 4 and t not in GENERIC_NAME_TOKENS]
        if key(claimed) and key(claimed) in key(label) or any(t in key(label) for t in tokens):
            return {"status": "name_in_domain", "official_domain": None}
        return {"status": "unverifiable", "official_domain": None,
                "note": "claimed brand is not in the reference catalog and its name is not in the domain"}


# ---------------------------------------------------------------- helpers

def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def visual_brand(sample_id: str, input_type: str, logos: dict, clips: dict) -> dict | None:
    """Accepted logo match first (more precise), else accepted whole-image CLIP brand."""
    logo = logos.get((sample_id, input_type))
    if logo and logo.get("best_brand"):
        return {"brand_id": logo["best_brand"], "similarity": logo["best_cosine"], "method": "logo_detector+clip_logo_match"}
    clip = clips.get((sample_id, input_type))
    if clip and clip.get("predicted_brand"):
        return {"brand_id": clip["predicted_brand"], "similarity": clip["confidence"], "method": "clip_zero_shot"}
    return None


def run_ocr_cache(records: list[dict], have_ocr: set[str], enabled: bool) -> dict[str, str]:
    cache = json.loads(OCR_CACHE.read_text(encoding="utf-8")) if OCR_CACHE.exists() else {}
    if not enabled:
        return cache
    from prepare_text_baseline import run_ocr
    from app.services.ocr_service import create_ocr_engine

    engine = create_ocr_engine(_bootstrap.load_settings())
    if not engine.is_available():
        print("[ocr] Tesseract unavailable; skipping")
        return cache
    OCR_CACHE.parent.mkdir(parents=True, exist_ok=True)
    todo = [r for r in records if r["sample_id"] not in have_ocr and r["sample_id"] not in cache and (r.get("post") or {}).get("images")]
    for index, record in enumerate(todo, 1):
        text, _ = run_ocr(record["post"]["images"], engine)
        cache[record["sample_id"]] = text
        if index % 100 == 0:
            print(f"  ... OCR {index}/{len(todo)}")
            OCR_CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    OCR_CACHE.parent.mkdir(parents=True, exist_ok=True)
    OCR_CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    return cache


def add_flag(flags: list[dict], code: str, severity: str, detail: str) -> None:
    flags.append({"code": code, "severity": severity, "detail": detail})


# ------------------------------------------------------------------- main

def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--clip", default=DEFAULT_CLIP)
    parser.add_argument("--no-ocr", action="store_true", help="Do not run Tesseract on images without OCR")
    args = parser.parse_args()
    started = time.time()

    records = read_jsonl(METADATA)
    brands = BrandIndex(read_jsonl(CATALOG))
    baseline = {row["sample_id"]: row for row in read_jsonl(TEXT_BASELINE)}
    clips = {(row["sample_id"], row["input_type"]): row for row in read_jsonl(CLIP_PREDICTIONS)}
    logos = {(row["sample_id"], row["input_type"]): row for row in read_jsonl(LOGO_RESULTS)}
    post_web = {row["sample_id"]: row for row in read_jsonl(POST_WEB)}
    captures: dict[str, dict] = {}
    for capture in read_jsonl(CAPTURES):
        if capture.get("final_registered_domain") or capture.get("status") == "captured":
            captures.setdefault(capture["sample_id"], capture)

    print("[ocr] collecting OCR text")
    have_ocr = {sid for sid, row in baseline.items() if row.get("ocr_text_clean")}
    ocr_cache = run_ocr_cache(records, have_ocr, not args.no_ocr)

    texts, ocrs = {}, {}
    for record in records:
        sid = record["sample_id"]
        texts[sid] = baseline[sid]["post_text_clean"] if sid in baseline else clean_text((record.get("post") or {}).get("text"))
        ocr = baseline[sid]["ocr_text_clean"] if sid in baseline and baseline[sid].get("ocr_text_clean") else clean_text(ocr_cache.get(sid))
        ocrs[sid] = ocr if len(ocr) >= MIN_OCR_CHARS else ""

    print(f"[clip] loading {args.clip}")
    model, processor = load_clip(args.clip)
    with_images = [r for r in records if any((ROOT / ref).exists() for ref in (r.get("post") or {}).get("images", []))]
    image_emb: dict[str, np.ndarray] = {}
    for start in range(0, len(with_images), 32):
        batch = with_images[start:start + 32]
        images = [letterbox(open_rgb(next(ROOT / ref for ref in r["post"]["images"] if (ROOT / ref).exists()))) for r in batch]
        for record, vector in zip(batch, embed_images(model, processor, images)):
            image_emb[record["sample_id"]] = vector
    need_text = [sid for sid in texts if texts[sid] and (sid in image_emb or ocrs[sid])]
    text_emb = {}
    for start in range(0, len(need_text), 64):
        chunk = need_text[start:start + 64]
        for sid, vector in zip(chunk, embed_texts(model, processor, [texts[s][:300] for s in chunk])):
            text_emb[sid] = vector
    with_ocr = [sid for sid in ocrs if ocrs[sid] and texts[sid]]
    ocr_emb = {}
    for start in range(0, len(with_ocr), 64):
        chunk = with_ocr[start:start + 64]
        for sid, vector in zip(chunk, embed_texts(model, processor, [ocrs[s][:300] for s in chunk])):
            ocr_emb[sid] = vector
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True)
    lexical = {}
    if with_ocr:
        tfidf.fit([texts[s] for s in with_ocr] + [ocrs[s] for s in with_ocr])
        post_vecs = tfidf.transform([texts[s] for s in with_ocr])
        ocr_vecs = tfidf.transform([ocrs[s] for s in with_ocr])
        for index, sid in enumerate(with_ocr):
            lexical[sid] = float(post_vecs[index].multiply(ocr_vecs[index]).sum())

    now = datetime.now(timezone.utc).isoformat()
    results = []
    coverage = Counter()
    for record in records:
        sid = record["sample_id"]
        labels = record.get("labels") or {}
        source = (record.get("source") or {}).get("source_dataset") or "manual"
        post = record.get("post") or {}
        text, ocr = texts[sid], ocrs[sid]
        flags: list[dict] = []
        comparisons: dict[str, dict] = {}

        # 1. post text <-> post image
        if sid in image_emb and sid in text_emb:
            score = cosine(text_emb[sid], image_emb[sid])
            comparisons["text_image"] = {"status": "computed", "clip_cosine": round(score, 4), "low_threshold": TEXT_IMAGE_LOW}
            if score < TEXT_IMAGE_LOW:
                add_flag(flags, "TEXT_IMAGE_LOW_ALIGNMENT", "low", f"post text and image are weakly related (CLIP {score:.2f})")
        else:
            comparisons["text_image"] = {"status": "not_available"}

        # 2. post text <-> OCR (semantic + lexical)
        if sid in ocr_emb and sid in text_emb:
            semantic = cosine(text_emb[sid], ocr_emb[sid])
            overlap = word_overlap(text, ocr)
            comparisons["text_ocr"] = {"status": "computed", "semantic_cosine": round(semantic, 4),
                                       "lexical_tfidf_cosine": round(lexical.get(sid, 0.0), 4),
                                       "ocr_words_in_post": overlap["ocr_in_post"], "ocr_new_words": overlap["ocr_new_words"]}
            if semantic < TEXT_OCR_SEMANTIC_LOW and lexical.get(sid, 0.0) < TEXT_OCR_LEXICAL_LOW:
                add_flag(flags, "TEXT_OCR_DIVERGENT", "low", "text in the image says something different from the caption")
        else:
            comparisons["text_ocr"] = {"status": "not_available"}

        # brands from each source
        claimed = (record.get("brand") or {}).get("claimed_brand")
        claimed_id = brands.resolve(claimed)
        text_brands = brands.mentions(text)
        ocr_brands = brands.mentions(ocr)
        post_visual = visual_brand(sid, "post_image", logos, clips)
        web_visual = visual_brand(sid, "website_screenshot", logos, clips)

        # 3. text <-> detected brand, 4. OCR <-> detected brand
        for name, mentioned, present in (("text_brand", text_brands, bool(text)), ("ocr_brand", ocr_brands, bool(ocr))):
            if post_visual and present:
                agree = post_visual["brand_id"] in mentioned
                comparisons[name] = {"status": "computed", "mentioned": mentioned, "detected": post_visual["brand_id"],
                                     "detection_method": post_visual["method"], "agree": agree}
                if mentioned and not agree:
                    add_flag(flags, "TEXT_VISUAL_BRAND_CONFLICT" if name == "text_brand" else "OCR_VISUAL_BRAND_CONFLICT", "medium",
                             f"{'caption' if name == 'text_brand' else 'image text'} names {', '.join(mentioned)} but the image shows {post_visual['brand_id']}")
            elif mentioned and present:
                comparisons[name] = {"status": "no_visual_brand", "mentioned": mentioned}
            else:
                comparisons[name] = {"status": "not_available", "mentioned": mentioned}
        if post_visual and not claimed_id and post_visual["brand_id"] not in text_brands + ocr_brands:
            add_flag(flags, "VISUAL_BRAND_UNMENTIONED", "low",
                     f"image looks like {post_visual['brand_id']} ({post_visual['method']}) but no text names it")

        # post brand (claimed > text > OCR > visual)
        if claimed:
            post_brand = {"name": claimed, "brand_id": claimed_id, "origin": "claimed"}
        elif text_brands:
            post_brand = {"name": brands.display(text_brands[0]), "brand_id": text_brands[0], "origin": "post_text"}
        elif ocr_brands:
            post_brand = {"name": brands.display(ocr_brands[0]), "brand_id": ocr_brands[0], "origin": "ocr"}
        elif post_visual:
            post_brand = {"name": brands.display(post_visual["brand_id"]), "brand_id": post_visual["brand_id"], "origin": "visual"}
        else:
            post_brand = None

        # destination
        capture = captures.get(sid)
        urls = [u for u in [*(post.get("embedded_urls") or []), (record.get("destination") or {}).get("original_url")] if u]
        original_domain = registered_domain(urls[0]) if urls else None
        final_domain = (capture or {}).get("final_registered_domain") or registered_domain((record.get("destination") or {}).get("final_url"))
        destination_domain = final_domain or (original_domain if original_domain not in SHORTENERS else None)
        destination = {"original_domain": original_domain, "final_domain": final_domain,
                       "domain_used": destination_domain, "shortener": original_domain in SHORTENERS,
                       "capture_status": (capture or {}).get("status")}

        # website brand (visual on screenshot > page title mention > official domain)
        title_brands = brands.mentions((capture or {}).get("page_title") or "")
        if web_visual:
            website_brand = {"brand_id": web_visual["brand_id"], "origin": web_visual["method"], "similarity": web_visual["similarity"]}
        elif title_brands:
            website_brand = {"brand_id": title_brands[0], "origin": "page_title"}
        elif destination_domain in brands.domain_to_brand:
            website_brand = {"brand_id": brands.domain_to_brand[destination_domain], "origin": "official_domain"}
        else:
            website_brand = None

        # 5. post brand <-> website brand
        if post_brand and website_brand:
            agree = post_brand["brand_id"] is not None and post_brand["brand_id"] == website_brand["brand_id"]
            comparisons["post_web_brand"] = {"status": "computed", "post": post_brand, "website": website_brand, "agree": agree}
            if not agree:
                severity = "medium" if website_brand["origin"] in ("clip_zero_shot",) or post_brand["origin"] == "visual" else "high"
                add_flag(flags, "POST_WEBSITE_BRAND_CONFLICT", severity,
                         f"post is about {post_brand['name']} but the website looks like {website_brand['brand_id']} ({website_brand['origin']})")
        else:
            comparisons["post_web_brand"] = {"status": "not_available", "post": post_brand, "website": website_brand}

        # 6. post image <-> website screenshot
        pair = post_web.get(sid)
        if pair and (capture or {}).get("status") == "captured":
            comparisons["post_web_image"] = {"status": "computed", "clip_cosine": pair["global_cosine"],
                                             "phash_distance": pair["global_phash_distance"],
                                             "best_logo_pair_cosine": pair["best_logo_pair_cosine"]}
            if pair["global_cosine"] < POST_WEB_VISUAL_LOW:
                add_flag(flags, "POST_WEBSITE_VISUAL_MISMATCH", "low", f"post image and landing page look unrelated (CLIP {pair['global_cosine']:.2f})")
        else:
            comparisons["post_web_image"] = {"status": "not_available"}

        # 7. claimed brand <-> destination domain
        brand_for_domain = post_brand if post_brand and post_brand["origin"] != "visual" else None
        if brand_for_domain and destination_domain:
            check = brands.domain_check(brand_for_domain["name"], brand_for_domain["brand_id"], destination_domain)
            comparisons["brand_domain"] = {"status": "computed", "brand": brand_for_domain["name"],
                                           "brand_origin": brand_for_domain["origin"], "domain": destination_domain, **check}
            severity = "high" if brand_for_domain["origin"] == "claimed" else "medium"
            if check["status"] == "lookalike":
                add_flag(flags, "LOOKALIKE_DOMAIN", "high",
                         f"{destination_domain} imitates {brand_for_domain['name']} (official {check['official_domain']})")
            elif check["status"] == "mismatch":
                add_flag(flags, "BRAND_DOMAIN_MISMATCH", severity,
                         f"{brand_for_domain['name']} is claimed but the link goes to {destination_domain} (official {check['official_domain']})")
        else:
            comparisons["brand_domain"] = {"status": "not_available",
                                           "reason": "shortened link not resolved" if destination["shortener"] and not final_domain else None}
        if destination["shortener"] and not final_domain:
            add_flag(flags, "UNRESOLVED_SHORT_LINK", "low", f"link uses the {original_domain} shortener and was not resolved")

        for name in comparisons:
            coverage[(name, comparisons[name]["status"])] += 1

        # 10. brand identity mismatch
        brand_flags = [f for f in flags if f["code"] in ("LOOKALIKE_DOMAIN", "BRAND_DOMAIN_MISMATCH", "POST_WEBSITE_BRAND_CONFLICT",
                                                          "TEXT_VISUAL_BRAND_CONFLICT", "OCR_VISUAL_BRAND_CONFLICT")]
        strongest = max((SEVERITY[f["severity"]] for f in brand_flags), default=0)
        mismatch = {"detected": bool(brand_flags), "strength": {0: None, 1: "weak", 2: "moderate", 3: "strong"}[strongest],
                    "reasons": [f["code"] for f in brand_flags]}

        # 12. evidence summary
        lines = []
        if post_brand:
            lines.append(f"Post brand: {post_brand['name']} (from {post_brand['origin'].replace('_', ' ')}).")
        if post_visual:
            lines.append(f"Image brand: {post_visual['brand_id']} via {post_visual['method']} (similarity {post_visual['similarity']:.2f}).")
        if destination_domain:
            lines.append(f"Destination: {destination_domain}" + (f" (via {original_domain})" if final_domain and original_domain != final_domain else "") + ".")
        if website_brand:
            lines.append(f"Website brand: {website_brand['brand_id']} (from {website_brand['origin'].replace('_', ' ')}).")
        lines.extend(f"[{f['severity'].upper()}] {f['detail']}." for f in sorted(flags, key=lambda f: -SEVERITY[f["severity"]]))
        if not flags:
            lines.append("No cross-source inconsistencies found in the available evidence.")
        max_severity = max((f["severity"] for f in flags), key=lambda s: SEVERITY[s], default=None)

        results.append({
            "sample_id": sid, "source": source, "is_scam": labels.get("is_scam"), "label_status": labels.get("label_status"),
            "comparisons": comparisons, "post_brand": post_brand, "website_brand": website_brand, "destination": destination,
            "brand_identity_mismatch": mismatch, "flags": flags, "max_severity": max_severity,
            "evidence_summary": " ".join(lines), "created_at": now,
        })

    for item in CHECKLIST:
        mark_checklist(item)
    RESULTS.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in results) + "\n", encoding="utf-8")

    # ---------------------------------------------------------- statistics
    flag_counts = Counter(f["code"] for row in results for f in row["flags"])
    by_label = defaultdict(Counter)
    for row in results:
        if row["label_status"] == "verified" and row["is_scam"] in (0, 1):
            group = "scam" if row["is_scam"] else "legit"
            by_label[group]["n"] += 1
            by_label[group]["any_flag"] += bool(row["flags"])
            by_label[group]["brand_mismatch"] += row["brand_identity_mismatch"]["detected"]
            by_label[group]["high_flag"] += row["max_severity"] == "high"
            for f in row["flags"]:
                by_label[group][f["code"]] += 1
    rates = {group: {k: (round(v / c["n"], 4) if k != "n" else v) for k, v in c.items()} for group, c in by_label.items()}
    scam, legit = by_label.get("scam", Counter()), by_label.get("legit", Counter())
    tp, fp = scam["brand_mismatch"], legit["brand_mismatch"]
    text_image = [row["comparisons"]["text_image"]["clip_cosine"] for row in results if row["comparisons"]["text_image"]["status"] == "computed"]
    STATISTICS.write_text(json.dumps({
        "samples": len(results),
        "coverage": {f"{name}:{status}": n for (name, status), n in sorted(coverage.items())},
        "flag_counts": dict(flag_counts.most_common()),
        "samples_with_flags": sum(bool(r["flags"]) for r in results),
        "brand_identity_mismatch": sum(r["brand_identity_mismatch"]["detected"] for r in results),
        "verified_label_rates": rates,
        "brand_mismatch_as_scam_signal": {
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / scam["n"], 4) if scam["n"] else None,
            "note": "Verified rows only. Flags are evidence for review, not labels.",
        },
        "text_image_cosine": {"n": len(text_image), "p10": round(float(np.percentile(text_image, 10)), 4) if text_image else None,
                              "median": round(float(np.median(text_image)), 4) if text_image else None},
        "thresholds": {"text_image_low": TEXT_IMAGE_LOW, "text_ocr_semantic_low": TEXT_OCR_SEMANTIC_LOW,
                       "text_ocr_lexical_low": TEXT_OCR_LEXICAL_LOW, "post_web_visual_low": POST_WEB_VISUAL_LOW,
                       "min_ocr_chars": MIN_OCR_CHARS},
        "models": {"clip": args.clip, "visual_brand": "logo detector match (>=0.78) else CLIP zero-shot (accepted)"},
        "runtime_seconds": round(time.time() - started, 1),
        "created_at": now,
    }, indent=2), encoding="utf-8")

    print(f"[coverage] {json.dumps({f'{n}:{s}': c for (n, s), c in sorted(coverage.items())})}")
    print(f"[flags] {dict(flag_counts.most_common())}")
    print(f"[labels] {json.dumps(rates)}")
    print(f"[brand mismatch as scam signal] precision={tp / (tp + fp) if tp + fp else None} recall={tp / scam['n'] if scam['n'] else None}")
    for row in results:
        if row["source"] == "manual":
            print(f"  {row['sample_id']} [{row['max_severity']}] {row['evidence_summary'][:220]}")
    print(f"Wrote {RESULTS} ({round(time.time() - started, 1)}s)")


if __name__ == "__main__":
    main()
