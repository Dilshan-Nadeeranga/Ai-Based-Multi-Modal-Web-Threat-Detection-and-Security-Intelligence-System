"""Public API routes: Part 2 preprocessing, Part 3 DOM features, Part 9 analysis (stub).

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from c2_analyzer.dom.pipeline import dom_features_for_html
from c2_analyzer.preprocessing.pipeline import preprocess_html
from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse
from c2_analyzer.schemas.dom import DomResult
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


@router.post("/api/v1/analyze", response_model=AnalysisResponse, tags=["analysis (Part 9)"])
def analyze(request: AnalysisRequest) -> AnalysisResponse:
    """Analyze raw HTML and return the unified tri-modal result."""
    # TODO (Part 9): return get_orchestrator().analyze(request)
    raise HTTPException(status_code=501, detail="Not implemented yet (Part 9)")


@router.post("/analyze-html", tags=["analysis (Part 9)"])
def analyze_html_legacy() -> None:
    """Compatibility route for backend/api-gateway, which calls
    ``POST {C2_URL}/analyze-html`` with ``{"url": ...}``.

    TODO (Part 9): agree with the gateway on one contract (URL vs raw HTML)
    and either fetch the page here or remove this route.
    """
    raise HTTPException(status_code=501, detail="Not implemented yet (Part 9)")
