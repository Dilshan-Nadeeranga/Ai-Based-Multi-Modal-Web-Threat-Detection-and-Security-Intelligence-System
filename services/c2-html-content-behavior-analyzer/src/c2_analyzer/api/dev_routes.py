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

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset, NotFoundError
from c2_analyzer.classifiers.dom_baseline.predict import PredictionError
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.schemas.dom_baseline import DomPrediction
from c2_analyzer.schemas.inspector import DomDictionaryInfo, SampleSummary, VersionInfo
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
