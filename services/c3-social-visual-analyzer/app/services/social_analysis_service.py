"""Live multimodal analysis of one social-media post (text + image + embedded URL).

Runs the trained C3 baselines on a single submission and returns every
intermediate result, so the dashboard can show the evidence behind the score:

  1. image preprocessing + duplicate check   (Phase 1 pipeline components)
  2. OCR                                     (Tesseract)
  3. text threat                             (DistilBERT text baseline)
  4. brand analysis                          (CLIP ViT-B/16 zero-shot, 24 reference brands)
  5. logo detection                          (YOLO11n logo detector + CLIP logo match)
  6. destination webpage capture             (sandboxed Playwright capturer)
  7. visual similarity                       (CLIP image cosine + pHash)
  8. cross-source consistency
  9. preliminary risk fusion                 (LOW / MEDIUM / HIGH)
 10. threat category classification          (text models + evidence rules, see threat_classifier)

Nothing is written to the research dataset: uploads go to a temporary
directory and are deleted after the request.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import re
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable

import numpy as np
from PIL import Image, ImageDraw

from app.config import SERVICE_ROOT, Settings
from app.exceptions import ServiceError
from app.services.image_pipeline import ImagePipeline
from app.services.image_preprocessor import convert_to_rgb, normalize_image, resize_image
from app.services.threat_classifier import RULE_STRONG, classify

logger = logging.getLogger(__name__)

MODELS_DIR = SERVICE_ROOT / "models"
TEXT_MODEL_DIR = MODELS_DIR / "text_baseline" / "distilbert-base-uncased"
CATEGORY_MODEL_DIR = MODELS_DIR / "threat_category" / "distilbert-base-uncased"
MISINFO_MODEL_DIR = MODELS_DIR / "misinformation" / "distilbert-base-uncased"
LOGO_DETECTOR = MODELS_DIR / "logo_detector" / "yolo11n_logo_baseline_best.pt"
CLIP_MODEL = "openai/clip-vit-base-patch16"

PLATFORMS = ("facebook", "instagram", "x", "tiktok", "whatsapp", "telegram", "reddit", "linkedin", "youtube", "other")

TEXT_TEMPLATES = (
    "the {name} logo",
    "a screenshot of the {name} website",
    "a {name} login page",
    "a social media post from {name}",
    "{name}",
)
THREAT_PROMPTS = (
    "a fake giveaway post asking people to click a link",
    "a scam advertisement promising free money or prizes",
    "a phishing login page asking for a password",
    "a fake bank or delivery notice asking for payment details",
    "a cryptocurrency investment scam post",
    "a fake job offer asking for a fee",
)
BENIGN_PROMPTS = (
    "an ordinary personal photo",
    "a normal news photo",
    "a legitimate company advertisement",
    "a meme or funny picture",
    "a screenshot of an ordinary website",
    "a photo of everyday objects or places",
)

# Same rule and thresholds as scripts/multimodal_risk_score.py and scripts/cross_source_consistency.py.
WEIGHTS = {"text": 0.50, "ocr": 0.15, "visual": 0.15, "website": 0.20}
BRAND_WEIGHT = 0.10
MISMATCH_BOOST = {"strong": 0.25, "moderate": 0.15, "weak": 0.05}
LOW_FLAG_BOOST, LOW_FLAG_CAP = 0.03, 0.09
HIGH_AT, MEDIUM_AT = 0.70, 0.40
TEXT_IMAGE_LOW = 0.18
TEXT_OCR_SEMANTIC_LOW = 0.60
TEXT_OCR_LEXICAL_LOW = 0.10
POST_WEB_VISUAL_LOW = 0.50
MIN_OCR_CHARS = 15
LOGIT_SCALE = 100.0
DETECTOR_CONF = 0.25

SHORTENERS = {"itl.ink", "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly",
              "s.id", "short.gy", "qrco.de", "clck.ru",
              "cutt.ly", "shorturl.at", "lnkd.in", "fb.me", "tiny.cc", "rb.gy", "t.ly"}
AMBIGUOUS_BRANDS = {"apple", "steam", "chase", "amazon", "orange", "square", "discord", "ups", "aruba", "bt"}
SEVERITY = {"low": 1, "medium": 2, "high": 3}

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_TAG = re.compile(r"<[^>]{1,200}>")
_ZERO_WIDTH = re.compile(r"[\u200b\u200e\u200f\u2060\ufeff]")
_SPACES = re.compile(r"\s+")


class AnalysisInputError(ServiceError):
    code = "INVALID_ANALYSIS_INPUT"
    status_code = 400


class ModelsUnavailableError(ServiceError):
    code = "MODELS_UNAVAILABLE"
    status_code = 503


# ---------------------------------------------------------------- helpers

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def clean_text(text: str | None) -> str:
    if not text:
        return ""
    import html
    import unicodedata

    value = unicodedata.normalize("NFKC", html.unescape(text))
    value = _TAG.sub(" ", value)
    value = _ZERO_WIDTH.sub("", value)
    return _SPACES.sub(" ", value).strip()[:4000]


def letterbox(image: Image.Image, fill: tuple[int, int, int] = (255, 255, 255)) -> Image.Image:
    width, height = image.size
    side = max(width, height)
    canvas = Image.new("RGB", (side, side), fill)
    canvas.paste(image, ((side - width) // 2, (side - height) // 2))
    return canvas


def logo_tile(path: Path) -> Image.Image:
    """Tight crop of a normalized (logo on white) reference image, flattened on white."""
    rgb = np.asarray(convert_to_rgb(Image.open(path)))
    mask = (rgb < 235).any(axis=2)
    ys, xs = np.where(mask)
    if not len(ys):
        return Image.fromarray(rgb)
    return Image.fromarray(rgb[ys.min():ys.max() + 1, xs.min():xs.max() + 1])


def to_data_url(image: Image.Image, fmt: str = "JPEG", max_side: int = 1280) -> str:
    copy = image.copy()
    copy.thumbnail((max_side, max_side))
    buffer = io.BytesIO()
    copy.save(buffer, format=fmt, quality=85)
    mime = "image/jpeg" if fmt == "JPEG" else "image/png"
    return f"data:{mime};base64,{base64.b64encode(buffer.getvalue()).decode('ascii')}"


def softmax(logits: np.ndarray) -> np.ndarray:
    shifted = np.exp(logits - logits.max())
    return shifted / shifted.sum()


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def registered_domain(url_or_host: str | None) -> str | None:
    if not url_or_host:
        return None
    import tldextract

    parts = tldextract.TLDExtract(suffix_list_urls=())(url_or_host)
    return f"{parts.domain}.{parts.suffix}".lower() if parts.domain and parts.suffix else None


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


# ------------------------------------------------------------------ models

@dataclass
class _Brand:
    brand_id: str
    display_name: str
    official_domain: str | None
    normalized_image: Path
    patterns: list[re.Pattern] = field(default_factory=list)


class SocialModels:
    """Lazily loaded models and reference embeddings, shared across requests."""

    def __init__(self) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, CLIPModel, CLIPProcessor

        try:
            import truststore

            truststore.inject_into_ssl()
        except ImportError:
            pass

        if not TEXT_MODEL_DIR.exists():
            raise ModelsUnavailableError("Text baseline model not found. Run scripts/train_text_baseline.py.")
        if not LOGO_DETECTOR.exists():
            raise ModelsUnavailableError("Logo detector weights not found. Run scripts/train_logo_detector.py.")

        self.torch = torch
        self.text_tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL_DIR)
        self.text_model = AutoModelForSequenceClassification.from_pretrained(TEXT_MODEL_DIR).eval()
        self.category_model = self.misinfo_model = None
        if CATEGORY_MODEL_DIR.exists():
            self.category_tokenizer = AutoTokenizer.from_pretrained(CATEGORY_MODEL_DIR)
            self.category_model = AutoModelForSequenceClassification.from_pretrained(CATEGORY_MODEL_DIR).eval()
        if MISINFO_MODEL_DIR.exists():
            self.misinfo_tokenizer = AutoTokenizer.from_pretrained(MISINFO_MODEL_DIR)
            self.misinfo_model = AutoModelForSequenceClassification.from_pretrained(MISINFO_MODEL_DIR).eval()
        self.clip_model = CLIPModel.from_pretrained(CLIP_MODEL).eval()
        self.clip_processor = CLIPProcessor.from_pretrained(CLIP_MODEL)

        from ultralytics import YOLO

        self.detector = YOLO(str(LOGO_DETECTOR))

        catalog = sorted((row for row in _read_jsonl(SERVICE_ROOT / "data" / "annotations" / "brand_catalog.jsonl")
                          if row.get("normalized_image") and row.get("status") != "duplicate_logo"),
                         key=lambda row: row["brand_id"])
        self.brands: list[_Brand] = []
        for row in catalog:
            brand = _Brand(row["brand_id"], row["display_name"], registered_domain(row.get("official_domain")),
                           SERVICE_ROOT / row["normalized_image"])
            names = {row["display_name"], *row.get("aliases", [])}
            flags = 0 if brand.brand_id in AMBIGUOUS_BRANDS else re.IGNORECASE
            if brand.brand_id not in AMBIGUOUS_BRANDS:
                names.add(brand.brand_id)
            brand.patterns = [re.compile(rf"(?<![\w]){re.escape(n)}(?![\w])", flags) for n in names if len(n) > 1]
            if row.get("official_domain"):
                brand.patterns.append(re.compile(rf"\b{re.escape(row['official_domain'])}\b", re.IGNORECASE))
            self.brands.append(brand)
        self.brand_ids = [b.brand_id for b in self.brands]
        self.by_id = {b.brand_id: b for b in self.brands}
        self.domain_to_brand = {b.official_domain: b.brand_id for b in self.brands if b.official_domain}

        text_vectors = []
        for brand in self.brands:
            prompts = [template.format(name=brand.display_name) for template in TEXT_TEMPLATES]
            vectors = self.embed_texts(prompts).mean(axis=0)
            text_vectors.append(vectors / np.linalg.norm(vectors))
        self.brand_text_emb = np.stack(text_vectors)
        normalized = [convert_to_rgb(Image.open(b.normalized_image)) for b in self.brands]
        self.brand_logo_emb = self.embed_images(normalized)
        self.ref_tiles = [logo_tile(b.normalized_image) for b in self.brands]
        self.ref_tile_emb = self.embed_images([letterbox(t) for t in self.ref_tiles])
        self.threat_prompt_emb = self.embed_texts(list(THREAT_PROMPTS + BENIGN_PROMPTS))

        clip_experiment = _read_json(SERVICE_ROOT / "data" / "statistics" / "clip_brand_experiment_clip-vit-base-patch16.json")
        logo_evaluation = _read_json(SERVICE_ROOT / "data" / "statistics" / "logo_baseline_evaluation.json")
        self.clip_mode = clip_experiment.get("selected_mode", "fused")
        self.clip_threshold = float(clip_experiment.get("selected_threshold", 0.67))
        self.logo_threshold = float(logo_evaluation.get("brand_threshold", 0.78))
        logger.info("Social analysis models loaded (%d brands, CLIP mode=%s t=%.2f, logo t=%.2f)",
                    len(self.brands), self.clip_mode, self.clip_threshold, self.logo_threshold)

    # --- encoders
    def _features(self, output):
        return output if isinstance(output, self.torch.Tensor) else output.pooler_output

    def embed_images(self, images: list[Image.Image]) -> np.ndarray:
        with self.torch.no_grad():
            inputs = self.clip_processor(images=images, return_tensors="pt")
            features = self._features(self.clip_model.get_image_features(pixel_values=inputs["pixel_values"]))
            return self.torch.nn.functional.normalize(features, dim=-1).numpy()

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        with self.torch.no_grad():
            inputs = self.clip_processor(text=texts, padding=True, truncation=True, return_tensors="pt")
            features = self._features(self.clip_model.get_text_features(
                input_ids=inputs["input_ids"], attention_mask=inputs["attention_mask"]))
            return self.torch.nn.functional.normalize(features, dim=-1).numpy()

    def scam_probability(self, text: str) -> float | None:
        if not text:
            return None
        with self.torch.no_grad():
            encoded = self.text_tokenizer([text], truncation=True, max_length=256, return_tensors="pt")
            return round(float(self.torch.softmax(self.text_model(**encoded).logits, dim=-1)[0, 1]), 4)

    def category_probabilities(self, text: str) -> dict[str, float] | None:
        if not text or self.category_model is None:
            return None
        with self.torch.no_grad():
            encoded = self.category_tokenizer([text], truncation=True, max_length=256, return_tensors="pt")
            probs = self.torch.softmax(self.category_model(**encoded).logits, dim=-1)[0].tolist()
        return {self.category_model.config.id2label[i]: round(p, 4) for i, p in enumerate(probs)}

    def misinformation_probability(self, text: str) -> float | None:
        if not text or self.misinfo_model is None:
            return None
        with self.torch.no_grad():
            encoded = self.misinfo_tokenizer([text], truncation=True, max_length=64, return_tensors="pt")
            return round(float(self.torch.softmax(self.misinfo_model(**encoded).logits, dim=-1)[0, 1]), 4)

    # --- brands
    def mentions(self, text: str) -> list[str]:
        found = {}
        for brand in self.brands:
            positions = [m.start() for p in brand.patterns if (m := p.search(text or ""))]
            if positions:
                found[brand.brand_id] = min(positions)
        return sorted(found, key=found.get)

    def clip_brand(self, views: list[Image.Image]) -> dict:
        view_emb = self.embed_images(views)
        text_sim = (view_emb @ self.brand_text_emb.T).max(axis=0)
        logo_sim = (view_emb @ self.brand_logo_emb.T).max(axis=0)
        logits = {"text": text_sim, "logo": logo_sim, "fused": 0.5 * (text_sim + logo_sim)}[self.clip_mode]
        probs = softmax(LOGIT_SCALE * logits)
        order = np.argsort(-probs)[:5]
        best = int(order[0])
        return {
            "mode": self.clip_mode, "threshold": self.clip_threshold,
            "predicted_brand": self.brand_ids[best] if probs[best] >= self.clip_threshold else None,
            "best_candidate": self.brand_ids[best], "confidence": round(float(probs[best]), 4),
            "top_k": [{"brand_id": self.brand_ids[i], "name": self.brands[i].display_name,
                       "probability": round(float(probs[i]), 4),
                       "text_cosine": round(float(text_sim[i]), 4), "logo_cosine": round(float(logo_sim[i]), 4)}
                      for i in order],
        }

    def detect_logos(self, image: Image.Image) -> list[dict]:
        import imagehash

        result = self.detector.predict(image, conf=DETECTOR_CONF, imgsz=640, device="cpu", max_det=20, verbose=False)[0]
        detections = []
        crops = []
        for box in result.boxes:
            x1, y1, x2, y2 = [float(v) for v in box.xyxy[0].tolist()]
            crop = image.crop((max(0, int(x1) - 4), max(0, int(y1) - 4),
                               min(image.width, int(x2) + 4), min(image.height, int(y2) + 4)))
            crops.append(crop)
            detections.append({"bbox": [round(x1, 1), round(y1, 1), round(x2, 1), round(y2, 1)],
                               "detector_confidence": round(float(box.conf[0]), 4)})
        if crops:
            embeddings = self.embed_images([letterbox(c) for c in crops])
            for det, emb, crop in zip(detections, embeddings, crops):
                sims = self.ref_tile_emb @ emb
                order = np.argsort(-sims)[:3]
                best = int(order[0])
                crop_hash = imagehash.phash(crop)
                det.update({
                    "brand_id": self.brand_ids[best] if sims[best] >= self.logo_threshold else None,
                    "best_candidate": self.brand_ids[best],
                    "label": self.brands[best].display_name if sims[best] >= self.logo_threshold else "logo",
                    "similarity": round(float(sims[best]), 4),
                    "phash_distance": int(crop_hash - imagehash.phash(self.ref_tiles[best])),
                    "top_k": [{"brand_id": self.brand_ids[i], "name": self.brands[i].display_name,
                               "cosine": round(float(sims[i]), 4)} for i in order],
                })
                det["_embedding"] = emb
        return detections

    def visual_threat(self, image_emb: np.ndarray) -> float:
        probs = softmax(LOGIT_SCALE * (self.threat_prompt_emb @ image_emb))
        return round(float(probs[:len(THREAT_PROMPTS)].sum()), 4)


# ---------------------------------------------------------------- service

def draw_detections(image: Image.Image, detections: list[dict]) -> Image.Image:
    canvas = image.copy()
    pen = ImageDraw.Draw(canvas)
    width = max(2, image.width // 300)
    for det in detections:
        colour = (239, 68, 68) if det.get("brand_id") else (250, 204, 21)
        pen.rectangle(det["bbox"], outline=colour, width=width)
        label = f"{det.get('label', 'logo')} {det.get('similarity', 0) * 100:.0f}% | det {det['detector_confidence'] * 100:.0f}%"
        x, y = det["bbox"][0], max(0, det["bbox"][1] - 16)
        pen.rectangle((x, y, x + 7 * len(label) + 6, y + 15), fill=colour)
        pen.text((x + 3, y + 1), label, fill=(0, 0, 0))
    return canvas


class SocialAnalysisService:
    """Runs the live analysis; models are loaded on first use."""

    def __init__(self, settings: Settings, pipeline: ImagePipeline,
                 capturer_factory: Callable[[Settings], Any] | None = None) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self._capturer_factory = capturer_factory
        self._models: SocialModels | None = None
        self._load_lock = threading.Lock()
        self._run_lock = threading.Lock()

    @property
    def models(self) -> SocialModels:
        with self._load_lock:
            if self._models is None:
                self._models = SocialModels()
            return self._models

    # ------------------------------------------------------------- analyze
    def analyze(self, *, platform: str, post_text: str, image_file: BinaryIO | None, image_filename: str | None,
                embedded_url: str | None, on_step: Callable[[dict], None] | None = None) -> dict:
        platform = (platform or "other").strip().lower()
        if platform not in PLATFORMS:
            raise AnalysisInputError(f"platform must be one of: {', '.join(PLATFORMS)}")
        post_text = (post_text or "").strip()
        if len(post_text) > self.settings.dataset_max_text_length:
            raise AnalysisInputError("post text is too long")
        embedded_url = (embedded_url or "").strip() or None
        if embedded_url and not re.match(r"^https?://", embedded_url, re.I):
            embedded_url = f"https://{embedded_url}"
        if not post_text and image_file is None and not embedded_url:
            raise AnalysisInputError("Provide post text, a post image or an embedded URL.")

        with self._run_lock:
            return self._run(platform, post_text, image_file, image_filename, embedded_url, on_step)

    def _run(self, platform: str, post_text: str, image_file: BinaryIO | None, image_filename: str | None,
             embedded_url: str | None, on_step: Callable[[dict], None] | None = None) -> dict:
        steps: list[dict] = []

        def emit(event: dict) -> None:
            if on_step is not None:
                on_step(dict(event))

        def finish(entry: dict) -> None:
            steps.append(entry)
            emit(entry)

        def step(key: str, label: str, fn: Callable[[], Any], skip_reason: str | None = None) -> Any:
            if skip_reason:
                finish({"key": key, "label": label, "status": "skipped", "detail": skip_reason, "duration_ms": 0})
                return None
            emit({"key": key, "label": label, "status": "running", "detail": None, "duration_ms": 0})
            started = time.perf_counter()
            try:
                value = fn()
                finish({"key": key, "label": label, "status": "done", "detail": None,
                        "duration_ms": round((time.perf_counter() - started) * 1000)})
                return value
            except ModelsUnavailableError:
                raise
            except Exception as exc:  # noqa: BLE001 - one failing stage must not hide the others
                logger.exception("Stage %s failed", key)
                finish({"key": key, "label": label, "status": "failed", "detail": str(exc)[:300],
                        "duration_ms": round((time.perf_counter() - started) * 1000)})
                return None

        models = self.models
        tmp_dir = Path(tempfile.mkdtemp(prefix="c3_live_"))
        try:
            pre = step("preprocessing", "Image preprocessing", lambda: self._preprocess(image_file, image_filename, tmp_dir),
                       None if image_file is not None else "no image uploaded")
            image: Image.Image | None = pre["rgb"] if pre and pre.get("valid") else None
            if pre and not pre.get("valid"):
                steps[-1]["status"] = "failed"
                steps[-1]["detail"] = pre["validation"]["error"]
                emit(steps[-1])

            ocr = step("ocr", "OCR extraction", lambda: self._ocr(image), None if image else "no valid image")
            text_clean = clean_text(post_text)
            ocr_clean = clean_text((ocr or {}).get("text"))
            ocr_for_model = ocr_clean if len(ocr_clean) >= MIN_OCR_CHARS else ""

            text_threat = step("text_threat", "Text threat analysis", lambda: {
                "post_text_score": models.scam_probability(text_clean),
                "ocr_text_score": models.scam_probability(ocr_for_model),
                "model": "DistilBERT text baseline (distilbert-base-uncased)",
            }, None if (text_clean or ocr_for_model) else "no text")

            image_emb = models.embed_images([letterbox(image)])[0] if image else None
            post_brand_clip = step("brand_analysis", "Brand analysis (CLIP)",
                                   lambda: models.clip_brand([letterbox(image), image]), None if image else "no valid image")
            post_logos = step("logo_detection", "Logo detection (YOLO)", lambda: models.detect_logos(image),
                              None if image else "no valid image")

            capture = step("web_capture", "Destination webpage capture", lambda: self._capture(embedded_url),
                           None if embedded_url else "no embedded URL")
            screenshot: Image.Image | None = capture.pop("_image", None) if capture else None
            website = None
            if screenshot is not None:
                website = {"clip": models.clip_brand([letterbox(screenshot), letterbox(
                    screenshot.crop((0, 0, max(1, screenshot.width // 2), max(1, screenshot.height // 3))))]),
                    "logos": models.detect_logos(screenshot)}

            visual = step("visual_similarity", "Visual similarity",
                          lambda: self._visual_similarity(image, screenshot, image_emb, post_logos or [], (website or {}).get("logos") or []),
                          None if image is not None and screenshot is not None else "needs both a post image and a captured webpage")

            consistency = step("consistency", "Cross-source consistency", lambda: self._consistency(
                text_clean, ocr_for_model, image_emb, post_brand_clip, post_logos or [], embedded_url, capture, website, visual))

            visual_threat = models.visual_threat(image_emb) if image_emb is not None else None
            risk = step("risk_fusion", "Preliminary risk fusion",
                        lambda: self._fuse(text_threat, visual_threat, post_brand_clip, post_logos or [], visual, consistency))
            classification = step("threat_classification", "Threat category classification",
                                  lambda: self._classify(text_clean, ocr_for_model, text_threat, embedded_url, capture,
                                                         consistency, risk))

            for det in (post_logos or []) + ((website or {}).get("logos") or []):
                det.pop("_embedding", None)

            top_brand = (consistency or {}).get("post_brand")
            reference = None
            brand_for_reference = (top_brand or {}).get("brand_id") or (post_brand_clip or {}).get("best_candidate")
            if brand_for_reference in models.by_id:
                reference = {"brand_id": brand_for_reference, "name": models.by_id[brand_for_reference].display_name,
                             "image": to_data_url(convert_to_rgb(Image.open(models.by_id[brand_for_reference].normalized_image)), "PNG", 256)}

            return {
                "success": True,
                "input": {"platform": platform, "post_text": post_text, "embedded_url": embedded_url,
                          "image_filename": image_filename},
                "pipeline": steps,
                "assessment": self._assessment(risk, consistency, post_brand_clip, post_logos or [], classification),
                "classification": classification,
                "preprocessing": {k: v for k, v in (pre or {}).items() if k != "rgb"} or None,
                "ocr": ocr,
                "text_threat": {**(text_threat or {}), "post_text": text_clean, "ocr_text": ocr_for_model} if text_threat else None,
                "brand_analysis": {"post_image": post_brand_clip, "website": (website or {}).get("clip"),
                                   "reference_logo": reference},
                "logo_detection": {
                    "detections": post_logos or [],
                    "annotated_image": to_data_url(draw_detections(image, post_logos or [])) if image else None,
                    "threshold": models.logo_threshold, "detector": "YOLO11n logo baseline",
                    "website_detections": (website or {}).get("logos") or [],
                    "website_annotated_image": to_data_url(draw_detections(screenshot, website["logos"])) if website else None,
                },
                "destination": capture,
                "visual_similarity": visual,
                "consistency": consistency,
                "risk": risk,
                "post_image": to_data_url(image) if image else None,
                "disclaimer": "Preliminary research prototype. Scores are evidence for analysts, not a verdict.",
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------- stages
    def _preprocess(self, image_file: BinaryIO, filename: str | None, tmp_dir: Path) -> dict:
        suffix = Path(filename or "upload.jpg").suffix.lower() or ".jpg"
        raw_path = tmp_dir / f"upload{suffix}"
        with raw_path.open("wb") as handle:
            shutil.copyfileobj(image_file, handle, length=1024 * 1024)
        pipeline = self.pipeline
        validation = pipeline.validator.validate(raw_path)
        if not validation.valid:
            return {"valid": False, "validation": validation.model_dump(mode="json")}
        image, original_mode, transposed = pipeline.preprocessor.load(raw_path)
        rgb = pipeline.preprocessor.to_rgb(image)
        processed = pipeline.preprocessor.resize(rgb)
        normalization = normalize_image(processed).info().model_dump(mode="json")
        phash = pipeline.hash_service.generate_phash(processed)
        duplicate = pipeline.duplicate_detector.find_duplicate(phash).model_dump(mode="json")
        checks = [
            {"label": "Valid image", "ok": True, "detail": f"{validation.format} {validation.width}x{validation.height}"},
            {"label": "RGB conversion", "ok": True, "detail": f"{original_mode} -> RGB"},
            {"label": "EXIF orientation", "ok": True, "detail": "corrected" if transposed else "no rotation needed"},
            {"label": "Resized", "ok": True, "detail": f"{processed.width}x{processed.height} (max {self.settings.processed_max_width})"},
            {"label": "Aspect ratio maintained", "ok": abs(processed.width / processed.height - rgb.width / rgb.height) < 0.02,
             "detail": f"{rgb.width / rgb.height:.3f} -> {processed.width / processed.height:.3f}"},
            {"label": "Normalized", "ok": True, "detail": f"{normalization['dtype']} [{normalization['min']:.2f}, {normalization['max']:.2f}]"},
            {"label": "Duplicate checked", "ok": True, "detail": f"compared with {duplicate['compared_against']} stored hashes"},
        ]
        return {"valid": True, "validation": validation.model_dump(mode="json"), "checks": checks,
                "phash": phash, "duplicate": duplicate, "rgb": rgb}

    def _ocr(self, image: Image.Image) -> dict:
        ocr_input = image
        if max(image.size) > self.settings.ocr_max_side:
            ocr_input = resize_image(image, self.settings.ocr_max_side, self.settings.ocr_max_side)
        result = self.pipeline.ocr_engine.extract(ocr_input)
        return {"text": result.text, "average_confidence": result.average_confidence, "word_count": result.word_count,
                "requested_languages": result.requested_languages, "used_languages": result.used_languages,
                "engine": result.engine, "engine_version": result.engine_version, "warning": result.warning}

    def _capture(self, url: str) -> dict:
        if not self.settings.web_capture_enabled:
            raise RuntimeError("web capture is disabled (WEB_CAPTURE_ENABLED=false)")
        short_link = None
        target = url
        if registered_domain(url) in SHORTENERS:
            from app.services.link_expander import expand_short_link
            from app.services.url_safety import UrlSafetyPolicy

            short_link = expand_short_link(url, UrlSafetyPolicy.from_settings(self.settings))
            target = short_link["expanded_url"] or url

        factory = self._capturer_factory
        if factory is None:
            from app.services.browser_capture import PlaywrightCapturer as factory  # noqa: N813
        with factory(self.settings) as capturer:
            page = capturer.capture(target)
        browser_chain = [hop.model_dump(mode="json") if hasattr(hop, "model_dump") else hop for hop in page.redirect_chain]
        expansion_hops = [hop for hop in (short_link or {}).get("hops", []) if hop["url"] != target] if target != url else []
        final_url = page.final_url or (target if target != url else None)
        result = {
            "original_url": url, "original_domain": registered_domain(url),
            "final_url": final_url, "final_domain": registered_domain(final_url),
            "http_status": page.http_status, "page_title": page.title,
            "short_link": short_link,
            "redirect_chain": expansion_hops + browser_chain,
            "blocked_requests": page.blocked_requests,
            "page_text": getattr(page, "page_text", None),
            "popups_blocked": getattr(page, "popups_blocked", 0), "dialogs": getattr(page, "dialogs", []),
            "downloads": getattr(page, "downloads", []), "notification_requests": getattr(page, "notification_requests", 0),
            "error_code": getattr(page.error_code, "value", page.error_code), "error_message": page.error_message,
            "screenshot": None, "captured": False,
        }
        if page.png:
            shot = convert_to_rgb(Image.open(io.BytesIO(page.png)))
            viewport = shot.crop((0, 0, shot.width, min(shot.height, int(shot.width * 0.75))))
            result.update({"screenshot": to_data_url(viewport), "captured": True,
                           "screenshot_size": [shot.width, shot.height], "_image": viewport})
        return result

    def _visual_similarity(self, image: Image.Image, screenshot: Image.Image, image_emb: np.ndarray,
                           post_logos: list[dict], web_logos: list[dict]) -> dict:
        import imagehash

        models = self.models
        web_emb = models.embed_images([letterbox(screenshot)])[0]
        pairs = [cosine(p["_embedding"], w["_embedding"]) for p in post_logos for w in web_logos
                 if "_embedding" in p and "_embedding" in w]
        return {"clip_cosine": round(cosine(image_emb, web_emb), 4),
                "phash_distance": int(imagehash.phash(image) - imagehash.phash(screenshot)),
                "best_logo_pair_cosine": round(max(pairs), 4) if pairs else None,
                "low_threshold": POST_WEB_VISUAL_LOW}

    def _consistency(self, text: str, ocr: str, image_emb, post_clip: dict | None, post_logos: list[dict],
                     url: str | None, capture: dict | None, website: dict | None, visual: dict | None) -> dict:
        models = self.models
        flags: list[dict] = []
        rows: list[dict] = []

        def flag(code: str, severity: str, detail: str) -> None:
            flags.append({"code": code, "severity": severity, "detail": detail})

        # semantic similarity
        text_emb = models.embed_texts([text[:300]])[0] if text else None
        if text_emb is not None and image_emb is not None:
            score = cosine(text_emb, image_emb)
            ok = score >= TEXT_IMAGE_LOW
            rows.append({"key": "text_image", "label": "Post Text ↔ Post Image", "value": round(score, 4),
                         "display": f"CLIP {score:.2f}", "status": "consistent" if ok else "inconsistent"})
            if not ok:
                flag("TEXT_IMAGE_LOW_ALIGNMENT", "low", f"post text and image are weakly related (CLIP {score:.2f})")
        else:
            rows.append({"key": "text_image", "label": "Post Text ↔ Post Image", "status": "not_available"})

        if text and ocr:
            from sklearn.feature_extraction.text import TfidfVectorizer

            semantic = cosine(text_emb, models.embed_texts([ocr[:300]])[0])
            vectors = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True).fit_transform([text, ocr])
            lexical = float(vectors[0].multiply(vectors[1]).sum())
            ok = not (semantic < TEXT_OCR_SEMANTIC_LOW and lexical < TEXT_OCR_LEXICAL_LOW)
            rows.append({"key": "text_ocr", "label": "Post Text ↔ OCR", "value": round(semantic, 4), "lexical": round(lexical, 4),
                         "display": f"semantic {semantic:.2f} · lexical {lexical:.2f}", "status": "consistent" if ok else "inconsistent"})
            if not ok:
                flag("TEXT_OCR_DIVERGENT", "low", "text inside the image says something different from the caption")
        else:
            rows.append({"key": "text_ocr", "label": "Post Text ↔ OCR", "status": "not_available"})

        # brands
        text_brands, ocr_brands = models.mentions(text), models.mentions(ocr)
        logo_hit = max((d for d in post_logos if d.get("brand_id")), key=lambda d: d["similarity"], default=None)
        if logo_hit:
            visual_brand = {"brand_id": logo_hit["brand_id"], "similarity": logo_hit["similarity"], "method": "YOLO logo + CLIP match"}
        elif post_clip and post_clip.get("predicted_brand"):
            visual_brand = {"brand_id": post_clip["predicted_brand"], "similarity": post_clip["confidence"], "method": "CLIP zero-shot"}
        else:
            visual_brand = None

        for key, label, mentioned, present in (("text_brand", "Text ↔ Detected Brand", text_brands, bool(text)),
                                               ("ocr_brand", "OCR ↔ Detected Brand", ocr_brands, bool(ocr))):
            if visual_brand and present and mentioned:
                agree = visual_brand["brand_id"] in mentioned
                rows.append({"key": key, "label": label, "display": f"{', '.join(mentioned)} ↔ {visual_brand['brand_id']}",
                             "status": "match" if agree else "mismatch"})
                if not agree:
                    flag("TEXT_VISUAL_BRAND_CONFLICT" if key == "text_brand" else "OCR_VISUAL_BRAND_CONFLICT", "medium",
                         f"{'caption' if key == 'text_brand' else 'image text'} names {', '.join(mentioned)} but the image shows {visual_brand['brand_id']}")
            elif mentioned and present:
                rows.append({"key": key, "label": label, "display": f"{', '.join(mentioned)} ↔ no visual brand", "status": "not_available"})
            elif visual_brand and present:
                rows.append({"key": key, "label": label, "display": f"no brand named ↔ {visual_brand['brand_id']}", "status": "not_available"})
            else:
                rows.append({"key": key, "label": label, "status": "not_available"})
        if visual_brand and visual_brand["brand_id"] not in text_brands + ocr_brands:
            flag("VISUAL_BRAND_UNMENTIONED", "low", f"image looks like {visual_brand['brand_id']} ({visual_brand['method']}) but no text names it")

        if text_brands:
            post_brand = {"brand_id": text_brands[0], "origin": "post text"}
        elif ocr_brands:
            post_brand = {"brand_id": ocr_brands[0], "origin": "OCR text"}
        elif visual_brand:
            post_brand = {"brand_id": visual_brand["brand_id"], "origin": visual_brand["method"]}
        else:
            post_brand = None
        if post_brand:
            post_brand["name"] = models.by_id[post_brand["brand_id"]].display_name

        # destination + website brand
        original_domain = registered_domain(url)
        final_domain = (capture or {}).get("final_domain")
        domain = final_domain or (original_domain if original_domain not in SHORTENERS else None)
        website_brand = None
        if website:
            logo_web = max((d for d in website["logos"] if d.get("brand_id")), key=lambda d: d["similarity"], default=None)
            if logo_web:
                website_brand = {"brand_id": logo_web["brand_id"], "origin": "YOLO logo + CLIP match", "similarity": logo_web["similarity"]}
            elif website["clip"].get("predicted_brand"):
                website_brand = {"brand_id": website["clip"]["predicted_brand"], "origin": "CLIP zero-shot",
                                 "similarity": website["clip"]["confidence"]}
        if website_brand is None and capture and capture.get("page_title"):
            title_brands = models.mentions(capture["page_title"])
            if title_brands:
                website_brand = {"brand_id": title_brands[0], "origin": "page title"}
        if website_brand is None and domain in models.domain_to_brand:
            website_brand = {"brand_id": models.domain_to_brand[domain], "origin": "official domain"}

        if post_brand and website_brand:
            agree = post_brand["brand_id"] == website_brand["brand_id"]
            rows.append({"key": "post_web_brand", "label": "Post Brand ↔ Website Brand",
                         "display": f"{post_brand['brand_id']} ↔ {website_brand['brand_id']}", "status": "match" if agree else "mismatch"})
            if not agree:
                severity = "medium" if "CLIP" in website_brand["origin"] or "CLIP" in post_brand["origin"] else "high"
                flag("POST_WEBSITE_BRAND_CONFLICT", severity,
                     f"post is about {post_brand['name']} but the website looks like {website_brand['brand_id']} ({website_brand['origin']})")
        else:
            rows.append({"key": "post_web_brand", "label": "Post Brand ↔ Website Brand", "status": "not_available"})

        if visual:
            ok = visual["clip_cosine"] >= POST_WEB_VISUAL_LOW
            rows.append({"key": "post_web_image", "label": "Post Image ↔ Website Screenshot", "value": visual["clip_cosine"],
                         "display": f"CLIP {visual['clip_cosine']:.2f} · pHash {visual['phash_distance']}",
                         "status": "consistent" if ok else "inconsistent"})
            if not ok:
                flag("POST_WEBSITE_VISUAL_MISMATCH", "low", f"post image and landing page look unrelated (CLIP {visual['clip_cosine']:.2f})")
        else:
            rows.append({"key": "post_web_image", "label": "Post Image ↔ Website Screenshot", "status": "not_available"})

        domain_check = {"status": "not_available"}
        if post_brand and domain:
            brand = models.by_id[post_brand["brand_id"]]
            label = domain.split(".")[0]
            if brand.official_domain and domain == brand.official_domain:
                domain_check = {"status": "official"}
            elif _key(brand.brand_id) in _key(label) or _key(brand.display_name) in _key(label):
                domain_check = {"status": "lookalike"}
                flag("LOOKALIKE_DOMAIN", "high", f"{domain} imitates {brand.display_name} (official {brand.official_domain})")
            else:
                domain_check = {"status": "mismatch"}
                severity = "medium" if "CLIP" in post_brand["origin"] else "high"
                flag("BRAND_DOMAIN_MISMATCH", severity,
                     f"{brand.display_name} is presented but the link goes to {domain} (official {brand.official_domain})")
            domain_check.update({"brand": brand.display_name, "domain": domain, "official_domain": brand.official_domain})
            rows.append({"key": "brand_domain", "label": "Claimed Brand ↔ Destination Domain",
                         "display": f"{brand.display_name} ↔ {domain}",
                         "status": {"official": "match", "lookalike": "mismatch", "mismatch": "mismatch"}[domain_check["status"]]})
        else:
            rows.append({"key": "brand_domain", "label": "Claimed Brand ↔ Destination Domain",
                         "display": f"{domain or 'no destination'}", "status": "not_available"})
        if original_domain in SHORTENERS and not final_domain:
            flag("UNRESOLVED_SHORT_LINK", "low", f"link uses the {original_domain} shortener and was not resolved")

        brand_codes = {"LOOKALIKE_DOMAIN", "BRAND_DOMAIN_MISMATCH", "POST_WEBSITE_BRAND_CONFLICT",
                       "TEXT_VISUAL_BRAND_CONFLICT", "OCR_VISUAL_BRAND_CONFLICT"}
        brand_flags = [f for f in flags if f["code"] in brand_codes]
        strongest = max((SEVERITY[f["severity"]] for f in brand_flags), default=0)
        return {
            "comparisons": rows, "flags": flags,
            "brand_identity_mismatch": {"detected": bool(brand_flags),
                                        "strength": {0: None, 1: "weak", 2: "moderate", 3: "strong"}[strongest],
                                        "reasons": [f["code"] for f in brand_flags]},
            "post_brand": post_brand, "visual_brand": visual_brand, "website_brand": website_brand,
            "domain_check": domain_check, "destination_domain": domain,
            "brands_in_text": text_brands, "brands_in_ocr": ocr_brands,
        }

    def _fuse(self, text_threat: dict | None, visual_threat: float | None, post_clip: dict | None,
              post_logos: list[dict], visual: dict | None, consistency: dict | None) -> dict:
        logo_best = max((d["similarity"] for d in post_logos), default=None)
        brand_values = [v for v in (logo_best, (post_clip or {}).get("confidence")) if v is not None]
        components = {
            "text": (text_threat or {}).get("post_text_score"),
            "ocr": (text_threat or {}).get("ocr_text_score"),
            "visual": visual_threat,
            "brand": round(max(brand_values), 4) if brand_values else None,
            "website": round(max(0.0, 1.0 - visual["clip_cosine"]), 4) if visual else None,
        }
        available = {k: v for k, v in components.items() if k in WEIGHTS and v is not None}
        total = sum(WEIGHTS[k] for k in available)
        base = sum(WEIGHTS[k] * v for k, v in available.items()) / total if total else 0.0
        reasons, boost = [], 0.0
        mismatch = (consistency or {}).get("brand_identity_mismatch") or {}
        flags = (consistency or {}).get("flags") or []
        if mismatch.get("detected"):
            boost += MISMATCH_BOOST[mismatch["strength"]]
            reasons.append(f"{mismatch['strength']} brand identity mismatch")
            if components["brand"] is not None:
                boost += BRAND_WEIGHT * components["brand"]
        brand_codes = set(mismatch.get("reasons") or [])
        low_flags = [f for f in flags if f["severity"] == "low" and f["code"] not in brand_codes]
        if low_flags:
            boost += min(LOW_FLAG_CAP, LOW_FLAG_BOOST * len(low_flags))
        score = min(1.0, base + boost)
        level = "HIGH" if score >= HIGH_AT else "MEDIUM" if score >= MEDIUM_AT else "LOW"
        if level == "LOW" and any(f["code"] == "LOOKALIKE_DOMAIN" or (f["code"] == "BRAND_DOMAIN_MISMATCH" and f["severity"] == "high")
                                  for f in flags):
            level = "MEDIUM"
            reasons.append("raised to MEDIUM: brand/domain mismatch")
        return {"components": components, "weights": WEIGHTS, "components_used": sorted(available),
                "base": round(base, 4), "boost": round(boost, 4), "score": round(score, 4), "level": level,
                "brand_mismatch": bool(mismatch.get("detected")), "reasons": reasons,
                "rule": {"HIGH": f">= {HIGH_AT}", "MEDIUM": f">= {MEDIUM_AT}", "LOW": f"< {MEDIUM_AT}"}}

    def _classify(self, text: str, ocr: str, text_threat: dict | None, url: str | None, capture: dict | None,
                  consistency: dict | None, risk: dict | None) -> dict:
        models = self.models
        combined = " ".join(filter(None, [text, ocr]))
        scam_scores = [v for v in ((text_threat or {}).get("post_text_score"), (text_threat or {}).get("ocr_text_score"))
                       if v is not None]
        result = classify(
            category_probs=models.category_probabilities(combined),
            misinformation_prob=models.misinformation_probability(text or ocr),
            scam_probability=max(scam_scores) if scam_scores else None,
            post_text=text, ocr_text=ocr, embedded_url=url, capture=capture, consistency=consistency, risk=risk,
        )
        result["models"] = {
            "category": "DistilBERT threat category (legitimate / phishing / financial_scam / data_theft)"
            if models.category_model is not None else None,
            "misinformation": "DistilBERT misinformation (Fakeddit titles)" if models.misinfo_model is not None else None,
        }
        if risk and risk.get("level") == "LOW" and result["primary"] in ("MALWARE", "BROWSER_ABUSE") and any(
                d["category"] == result["primary"] and d["score"] >= RULE_STRONG for d in result["detected"]):
            risk["level"] = "MEDIUM"
            risk["reasons"].append(f"raised to MEDIUM: strong {result['primary_label'].lower()} evidence")
        return result

    def _assessment(self, risk: dict | None, consistency: dict | None, post_clip: dict | None, logos: list[dict],
                    classification: dict | None = None) -> dict:
        consistency = consistency or {}
        risk = risk or {}
        components = risk.get("components") or {}
        mismatch = (consistency.get("brand_identity_mismatch") or {}).get("detected")
        brand = consistency.get("post_brand")
        primary = (classification or {}).get("primary")
        threat = (classification or {}).get("primary_label") or "Not available"
        domain_status = (consistency.get("domain_check") or {}).get("status")
        domain_match = {"official": "PASSED", "lookalike": "FAILED", "mismatch": "FAILED"}.get(domain_status, "NOT AVAILABLE")

        evidence: list[dict] = []
        visual = consistency.get("visual_brand")
        if visual:
            evidence.append({"ok": True, "text": f"{visual['brand_id']} visual identity detected in the post image "
                                                 f"({visual['method']}, {visual['similarity'] * 100:.0f}%)."})
        if components.get("ocr") is not None:
            evidence.append({"ok": components["ocr"] < 0.5, "text": f"Text inside the image scored {components['ocr'] * 100:.0f}% scam-like."})
        if components.get("text") is not None:
            evidence.append({"ok": components["text"] < 0.5, "text": f"Post caption scored {components['text'] * 100:.0f}% scam-like."})
        website_brand = consistency.get("website_brand")
        if website_brand:
            evidence.append({"ok": True, "text": f"Linked webpage resembles {website_brand['brand_id']} ({website_brand['origin']})."})
        for item in consistency.get("flags") or []:
            evidence.append({"ok": False, "text": item["detail"][0].upper() + item["detail"][1:] + "."})
        if domain_status == "official":
            evidence.append({"ok": True, "text": "Destination domain matches the brand's official domain."})

        level = risk.get("level", "LOW")
        others = [d["label"].lower() for d in (classification or {}).get("detected", []) if d["category"] != primary]
        also = f" Also indicates: {', '.join(others)}." if others else ""
        if primary == "BRAND_IMPERSONATION" and mismatch and brand:
            conclusion = f"Possible {brand['name']} brand-impersonation attack.{also}"
        elif primary and primary != "LEGITIMATE":
            conclusion = f"Most likely category: {threat.lower()} (risk {level}).{also}"
        elif level == "HIGH":
            conclusion = "Strong scam indicators in the available evidence."
        elif level == "MEDIUM":
            conclusion = "Some suspicious indicators; review recommended."
        else:
            conclusion = "No strong scam indicators in the available evidence."
        return {
            "level": level, "score": risk.get("score"), "detected_threat": threat,
            "detected_brand": (brand or {}).get("name") or ((post_clip or {}).get("predicted_brand")),
            "domain_match": domain_match, "evidence": evidence, "conclusion": conclusion,
            "detected_categories": (classification or {}).get("detected", []),
            "threat_rule": "hybrid: text models (phishing / financial scam / data theft / misinformation) + evidence "
                           "rules (brand impersonation, malware, browser abuse, other scam)",
        }


# --------------------------------------------------------------- results

def dataset_overview() -> dict:
    """Saved summaries of the C3 datasets other than the multimodal dataset (read-only)."""
    stats = SERVICE_ROOT / "data" / "statistics"
    brand = _read_json(stats / "brand_dataset_statistics.json")
    yolo = _read_json(stats / "logo_yolo_dataset_statistics.json")
    text = _read_json(stats / "text_baseline_metrics.json")
    category = _read_json(stats / "threat_category_metrics.json")
    misinfo = _read_json(stats / "misinformation_metrics.json")
    binary_names = {"0": "legitimate", "1": "scam"}
    tp_phish, tp_legit, tp_candidates, tp_experiment = (_read_json(stats / name) for name in (
        "telephish_import_phishing.json", "telephish_import_legitimate.json", "telephish_candidates.json",
        "telephish_experiment.json"))
    telephish = None
    if tp_phish or tp_candidates:
        categories = {"phishing": (tp_phish.get("counts") or {}).get("imported", 0),
                      "legitimate": (tp_legit.get("counts") or {}).get("imported", 0)}
        for name in ("brand_impersonation", "financial_scam", "malware"):
            categories[name] = ((tp_candidates.get("candidates") or {}).get(name) or {}).get("total", 0)
        telephish = {
            "source": tp_phish.get("source") or tp_candidates.get("source"),
            "source_url": tp_phish.get("source_url") or tp_candidates.get("source_url"),
            "licence": tp_phish.get("licence") or tp_candidates.get("licence"),
            "label_basis": "VirusTotal URL flags (provisional); categories by evidence rules + review",
            "categories": categories,
            "brand_impersonation_by_brand": tp_candidates.get("brand_impersonation_by_brand"),
            "excluded": {k: v for k, v in (tp_candidates.get("counts") or {}).items() if k.startswith("excluded")},
            "used_in_training": False,
            "experiment_decision": tp_experiment.get("decision"),
        }
    smish = _read_json(stats / "smishtank_import.json")
    smishtank = None
    if smish:
        categories = {name: (smish.get("categories") or {}).get(name, 0) for name in (
            "phishing", "brand_impersonation", "financial_scam", "data_theft", "malware", "other_scam")}
        categories["malware"] = smish.get("malware_candidates", 0)
        impersonation = smish.get("brand_impersonation") or {}
        smishtank = {
            "source": smish.get("source"), "source_url": smish.get("source_url"), "licence": smish.get("licence"),
            "platform": smish.get("platform"), "label_basis": smish.get("label_basis"),
            "categories": categories,
            "category_note": "malware = messages whose URL VirusTotal flagged as malware (candidates, not labels)",
            "brand_impersonation_by_brand": impersonation.get("top_brands"),
            "brand_summary": {k: impersonation.get(k) for k in ("distinct_brands", "catalog_brands_covered",
                                                                 "messages_for_catalog_brands")},
            "url_types": smish.get("url_types"),
            "excluded": {"near_duplicates": (smish.get("counts") or {}).get("near_duplicates", 0),
                         "too_short": (smish.get("counts") or {}).get("too_short", 0)},
            "used_in_training": False,
        }
    return {
        "external": {"telephish": telephish, "smishtank": smishtank},
        "brand_reference": {k: brand.get(k) for k in (
            "generated_at", "brands_in_catalog", "primary_logos_on_disk", "normalized_logos_on_disk", "screenshots_on_disk",
            "logo_annotations", "logo_boxes", "split_counts", "categories")} if brand else None,
        "logo_detector": {k: yolo.get(k) for k in (
            "created_at", "classes", "counts", "dom_page_labels", "dom_box_kinds_note", "synthetic_brands_by_split")} if yolo else None,
        "training_splits": {
            "text_baseline": {split: {binary_names.get(k, k): v for k, v in counts.items()}
                              for split, counts in (text.get("label_counts") or {}).items()} or None,
            "threat_category": category.get("label_counts"),
            "misinformation": misinfo.get("label_counts"),
        },
    }


def model_results() -> dict:
    """Saved evaluation metrics from the C3 experiments (read-only)."""
    stats = SERVICE_ROOT / "data" / "statistics"
    text = _read_json(stats / "text_baseline_metrics.json")
    category = _read_json(stats / "threat_category_metrics.json")
    misinfo = _read_json(stats / "misinformation_metrics.json")
    clip = _read_json(stats / "clip_brand_experiment_clip-vit-base-patch16.json")
    clip_b32 = _read_json(stats / "clip_brand_experiment_clip-vit-base-patch32.json")
    logo_train = _read_json(stats / "logo_detector_training.json")
    logo_eval = _read_json(stats / "logo_baseline_evaluation.json")
    consistency = _read_json(stats / "consistency_statistics.json")
    risk = _read_json(stats / "risk_score_statistics.json")
    brand_stats = _read_json(stats / "brand_dataset_statistics.json")

    def pick(data: dict, *path: str):
        for key in path:
            if not isinstance(data, dict):
                return None
            data = data.get(key)
        return data

    return {
        "text_baseline": {
            "model": text.get("model"), "best_epoch": text.get("best_epoch"),
            "validation": {k: pick(text, "validation", k) for k in ("accuracy", "precision_scam", "recall_scam", "f1_scam")},
            "test": {k: pick(text, "test", k) for k in ("accuracy", "precision_scam", "recall_scam", "f1_scam")},
            "confusion_matrix": pick(text, "test", "confusion_matrix"),
            "test_by_source": text.get("test_by_source"),
        },
        **{key: {k: data.get(k) for k in ("model", "labels", "best_epoch", "label_counts", "validation", "test",
                                          "test_by_group", "unlabelled_categories", "notes")} if data else None
           for key, data in (("threat_category", category), ("misinformation", misinfo))},
        "clip_brand": {
            "model": clip.get("model"), "mode": clip.get("selected_mode"), "threshold": clip.get("selected_threshold"),
            "zenodo_test": pick(clip, "results", "zenodo_test", clip.get("selected_mode") or "fused"),
            "official_homepages": pick(clip, "results", "official_homepages"),
            "b32_zenodo_test": pick(clip_b32, "results", "zenodo_test", clip_b32.get("selected_mode") or "fused"),
        },
        "logo_detector": {"config": logo_train.get("config"), "metrics": logo_train.get("metrics"),
                          "detection_at_conf": logo_eval.get("detection_at_conf"),
                          "brand_matching_test": logo_eval.get("brand_matching_test"),
                          "brand_threshold": logo_eval.get("brand_threshold")},
        "consistency": {k: consistency.get(k) for k in ("samples", "flag_counts", "samples_with_flags",
                                                         "brand_identity_mismatch", "verified_label_rates",
                                                         "brand_mismatch_as_scam_signal")},
        "risk_score": {k: risk.get(k) for k in ("level_counts", "evaluation_test_split", "manual_posts", "fusion_rule")},
        "brand_reference": brand_stats or None,
    }
