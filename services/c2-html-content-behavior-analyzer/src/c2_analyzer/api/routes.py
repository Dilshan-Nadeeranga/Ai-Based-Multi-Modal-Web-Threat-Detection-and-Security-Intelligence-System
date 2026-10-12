"""API routes (stubs until Part 9 is implemented).

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse

router = APIRouter()


@router.post("/api/v1/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest) -> AnalysisResponse:
    """Analyze raw HTML and return the unified tri-modal result."""
    # TODO (Part 9): return get_orchestrator().analyze(request)
    raise HTTPException(status_code=501, detail="Not implemented yet (Part 9)")


@router.post("/analyze-html")
def analyze_html_legacy() -> None:
    """Compatibility route for backend/api-gateway, which calls
    ``POST {C2_URL}/analyze-html`` with ``{"url": ...}``.

    TODO (Part 9): agree with the gateway on one contract (URL vs raw HTML)
    and either fetch the page here or remove this route.
    """
    raise HTTPException(status_code=501, detail="Not implemented yet (Part 9)")
