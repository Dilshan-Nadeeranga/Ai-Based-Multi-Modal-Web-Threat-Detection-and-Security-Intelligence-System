"""Developer-only routes: dataset browsing API + the inspector page.

Developer tooling (added after Part 2). Registered by ``main.create_app`` ONLY
when APP_ENV=development; in any other environment these paths return 404.

Why dev-only: they expose dataset samples (real scam pages) and file-system
backed data. That is fine on a developer laptop bound to 127.0.0.1, but must
never be reachable on a deployed service.

XSS rule (viva): every page in the dataset is hostile. The inspector shows
facts ABOUT pages, never the pages themselves:
- JSON endpoints return data; the inspector renders it as text only
  (see the rule at the top of static/inspector.js).
- The only HTML ever served from a page is Part 1's sanitized safe preview,
  with a CSP that allows no scripts and no outside loads, ``nosniff``, and it
  is shown in an ``<iframe sandbox="">`` (no scripts, opaque origin).
- Nothing here fetches a live URL.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse, HTMLResponse

from c2_analyzer.api.dependencies import (
    AnalysisEngine,
    get_dev_dataset,
    get_engine,
    get_text_models,
)
from c2_analyzer.api.dev_data import DevDataset, NotFoundError
from c2_analyzer.classifiers.dom_baseline.predict import PredictionError
from c2_analyzer.fusion.orchestrator import BudgetExceeded
from c2_analyzer.fusion.predictor import FusionStale
from c2_analyzer.nlp.inference import TextModelRegistry
from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse
from c2_analyzer.schemas.behavior import BehaviorResult
from c2_analyzer.schemas.content import PageText
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.schemas.dom_baseline import DomPrediction
from c2_analyzer.schemas.fusion import FusionExplanation
from c2_analyzer.schemas.inspector import DomDictionaryInfo, SampleSummary, VersionInfo
from c2_analyzer.schemas.js import JsAnalysisResult
from c2_analyzer.schemas.nlp import TextPrediction
from c2_analyzer.schemas.parsed_page import ParsedPage

STATIC_DIR = Path(__file__).parent / "static"

# The sanitized preview may use inline CSS (the page layout) and nothing else.
SAFE_PREVIEW_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; "
    "base-uri 'none'; frame-ancestors 'self'"
)
# Same policy as the <meta> tag in inspector.html (the header is the stronger copy).
INSPECTOR_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
NO_STORE = {"Cache-Control": "no-store"}
DatasetDep = Annotated[DevDataset, Depends(get_dev_dataset)]  # tests override get_dev_dataset
TextModelsDep = Annotated[TextModelRegistry, Depends(get_text_models)]  # tests override it
EngineDep = Annotated[AnalysisEngine, Depends(get_engine)]  # tests override get_engine

router = APIRouter(prefix="/api/v1/dev", tags=["developer inspector (APP_ENV=development)"])
inspector_router = APIRouter()


def _version(dataset: DevDataset, version: str | None) -> str:
    try:
        return version or dataset.latest_version()
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None


@router.get("/versions", response_model=list[VersionInfo], summary="Frozen dataset versions")
def versions(dataset: DatasetDep) -> list[VersionInfo]:
    """Frozen dataset versions (Part 1 manifests), newest first, with Part 2 progress."""
    return dataset.versions()


@router.get("/samples", response_model=list[SampleSummary], summary="Samples of a version")
def samples(
    dataset: DatasetDep,
    version: str | None = Query(None, examples=["v0.1"], description="default: newest"),
    label: str | None = Query(None, examples=["phishing"]),
    language: str | None = Query(None, examples=["si"]),
    q: str | None = Query(None, max_length=200, description="search in sample id and title"),
    has_password: bool | None = Query(None),
    external_form_action: bool | None = Query(None),
    has_critical_behavior: bool | None = Query(
        None, description="stored Part 8 result has a critical finding"
    ),
    misclassified: bool | None = Query(
        None, description="test pages the best Part 4 baseline got wrong"
    ),
) -> list[SampleSummary]:
    """Manifest rows + facts from the stored Part 2 JSON (pages are not re-parsed)."""
    try:
        return dataset.samples(
            _version(dataset, version),
            label,
            language,
            q,
            has_password,
            external_form_action,
            misclassified,
            has_critical_behavior,
        )
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None


@router.get(
    "/samples/{sample_id}/parsed",
    response_model=ParsedPage,
    summary="Stored ParsedPage of a sample",
)
def parsed(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.1"], description="default: newest"),
) -> Response:
    """The stored Part 2 JSON; processed on the fly (not saved) if it is missing.

    Header ``X-Parsed-Source`` says which: ``stored`` or ``on-the-fly``.
    """
    try:
        text, source = dataset.parsed(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return Response(text, media_type="application/json", headers={"X-Parsed-Source": source})


@router.get(
    "/samples/{sample_id}/dom-features",
    response_model=DomResult,
    summary="Part 3 DOM features + evidence of a sample",
)
def dom_features(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.1"], description="default: newest"),
) -> Response:
    """The stored DomResult; computed on the fly (not saved) if missing or outdated.

    Header ``X-Features-Source`` says which: ``stored`` or ``on-the-fly``.
    """
    try:
        text, source = dataset.dom_features(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return Response(text, media_type="application/json", headers={"X-Features-Source": source})


@router.get(
    "/samples/{sample_id}/js-analysis",
    response_model=JsAnalysisResult,
    summary="Part 7 static JavaScript analysis of a sample",
)
def js_analysis(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.2"], description="default: newest"),
) -> Response:
    """The stored JsAnalysisResult; computed on the fly (not saved) if missing or outdated.

    Header ``X-Js-Source`` says which: ``stored`` or ``on-the-fly``.
    """
    try:
        text, source = dataset.js_analysis(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return Response(text, media_type="application/json", headers={"X-Js-Source": source})


@router.get(
    "/samples/{sample_id}/behavior",
    response_model=BehaviorResult,
    summary="Part 8 behavioral intent mapping of a sample",
)
def behavior(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.3"], description="default: newest"),
) -> Response:
    """The stored BehaviorResult; computed on the fly (not saved) if missing or outdated.

    Header ``X-Behavior-Source`` says which: ``stored`` or ``on-the-fly``.
    """
    try:
        text, source = dataset.behavior(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return Response(text, media_type="application/json", headers={"X-Behavior-Source": source})


@router.get(
    "/samples/{sample_id}/content",
    response_model=PageText,
    summary="Part 5 text segments + language ID of a sample",
)
def content(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.3"], description="default: newest"),
) -> Response:
    """The stored PageText; computed on the fly (not saved) if missing or outdated.

    Header ``X-Content-Source`` says which: ``stored`` or ``on-the-fly``.
    """
    try:
        text, source = dataset.content(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return Response(text, media_type="application/json", headers={"X-Content-Source": source})


@router.get(
    "/samples/{sample_id}/text-prediction",
    response_model=TextPrediction,
    summary="Part 6A text models (XLM-R + TF-IDF) on a sample's page_text",
)
def text_prediction(
    dataset: DatasetDep,
    models: TextModelsDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.3"], description="default: newest"),
) -> TextPrediction:
    """Predictions of the models trained on ``version`` for the sample's Part 5A page_text.

    A model that is missing answers ``available: false`` ("model not available") -
    still 200. 404 only for an unknown sample / version.
    """
    chosen = _version(dataset, version)
    try:
        text, _ = dataset.content(chosen, sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    page = PageText.model_validate_json(text)
    prediction = models.get(chosen).predict(
        page.page_text, page_language=page.language.language, sample_id=sample_id
    )
    prediction.true_label = dataset.label_of(chosen, sample_id)
    prediction.split = dataset.split_of(chosen, sample_id)
    return prediction


@router.get(
    "/samples/{sample_id}/fusion",
    response_model=FusionExplanation,
    summary="Part 9A fusion model: per-arm probabilities, fused verdict, drivers",
)
def fusion(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.3"], description="default: newest"),
) -> FusionExplanation:
    """The saved fusion model's answer for a dataset sample, from the STORED arm
    probabilities (out-of-fold for train / val pages, final arm models for test pages):
    per-arm probabilities, fused probabilities, argmax verdict, the verdict at the benign
    threshold (OOF benign FPR <= 2 %) and which arm / feature drove it.

    404 unknown sample / no fusion model; 409 the model or its OOF tables are stale.
    """
    try:
        return dataset.fusion(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except FusionStale as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@router.get(
    "/samples/{sample_id}/analysis",
    response_model=AnalysisResponse,
    summary="Part 9 B-1 unified analysis of a sample (POST /api/v1/analyze in html mode)",
)
def analysis(
    dataset: DatasetDep,
    engine: EngineDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.3"], description="default: newest"),
) -> Response:
    """The full live pipeline on the sample's stored HTML + its page URL (never fetched):
    exactly what ``POST /api/v1/analyze {html, url}`` returns for it. 404 unknown sample,
    503 models not loaded, 504 time budget exceeded (partial result)."""
    try:
        html, url = dataset.raw_html(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    try:
        orchestrator = engine.get()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=f"models not loaded: {error}") from None
    request = AnalysisRequest(html=html, url=url, request_id=sample_id, source="api")
    try:
        result = orchestrator.analyze(request)
    except BudgetExceeded as late:
        return Response(late.response.model_dump_json(), 504, media_type="application/json")
    return Response(result.model_dump_json(), media_type="application/json")


@router.get(
    "/samples/{sample_id}/dom-prediction",
    response_model=DomPrediction,
    summary="Part 4 DOM baseline prediction of a sample",
)
def dom_prediction(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, examples=["v0.1"], description="default: newest"),
) -> DomPrediction:
    """Probabilities of every trained baseline + the best model's top 5 feature pushes.

    404 if no baseline was trained for the version; 409 if the models no longer
    fit the current feature dictionary (retrain).
    """
    try:
        return dataset.dom_prediction(_version(dataset, version), sample_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except PredictionError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@router.get(
    "/dom-dictionary",
    response_model=DomDictionaryInfo,
    summary="Part 3 feature dictionary + per-label medians",
)
def dom_dictionary(
    dataset: DatasetDep,
    version: str | None = Query(None, examples=["v0.1"], description="medians of this version"),
) -> DomDictionaryInfo:
    """Names, groups, descriptions; medians per label from reports/dom_features (if run)."""
    try:
        chosen = version or dataset.latest_version()
    except NotFoundError:
        chosen = None
    return dataset.dom_dictionary(chosen)


@router.get(
    "/samples/{sample_id}/safe-preview",
    response_class=HTMLResponse,
    summary="Sanitized copy of a sample (for a sandboxed iframe)",
)
def safe_preview(
    dataset: DatasetDep,
    sample_id: str,
    version: str | None = Query(None, description="default: newest version listing it"),
) -> HTMLResponse:
    """Part 1's safe preview: no scripts, no URLs, no forms, plus a strict CSP header."""
    try:
        html = dataset.safe_preview(sample_id, version)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return HTMLResponse(
        html,
        headers={
            "Content-Security-Policy": SAFE_PREVIEW_CSP,
            "X-Content-Type-Options": "nosniff",
            **NO_STORE,
        },
    )


@inspector_router.get("/inspector", include_in_schema=False)
def inspector_page() -> FileResponse:
    """The developer inspector (static HTML; all data comes from the JSON endpoints)."""
    return FileResponse(
        STATIC_DIR / "inspector.html",
        media_type="text/html; charset=utf-8",
        headers={"Content-Security-Policy": INSPECTOR_CSP, **NO_STORE},
    )


@inspector_router.get("/inspector/inspector.js", include_in_schema=False)
def inspector_script() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "inspector.js",
        media_type="text/javascript; charset=utf-8",
        headers=NO_STORE,
    )
