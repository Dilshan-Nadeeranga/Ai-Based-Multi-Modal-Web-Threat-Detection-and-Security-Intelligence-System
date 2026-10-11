"""API routes for URL feature extraction and lexical intelligence analysis."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.database import save_scan_result
from app.schemas.url_schema import (
    Layer1LexicalAnalysisResult,
    UrlAnalysisRequest,
    UrlLexicalFeatures,
)

router = APIRouter(tags=["URL Analysis"])
analyzer = UrlLexicalAnalyzer()


@router.post(
    "/analyze-url",
    response_model=Layer1LexicalAnalysisResult,
    summary="Analyze URL & extract lexical features (Gateway endpoint)",
)
@router.post(
    "/api/v1/analyze-url",
    response_model=Layer1LexicalAnalysisResult,
    summary="Analyze URL & extract lexical features (v1 API)",
)
async def analyze_url(payload: UrlAnalysisRequest) -> Layer1LexicalAnalysisResult:
    """Analyze a URL or domain without executing or rendering destination webpages.

    Extracts 30+ numerical, boolean, entropy, and structural features suitable for machine
    learning inference and heuristic security scoring.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    result = analyzer.analyze(payload.url)

    # Optionally persist result if database is connected
    save_scan_result(result.model_dump())

    return result


@router.post(
    "/api/v1/extract-features",
    response_model=UrlLexicalFeatures,
    summary="Extract raw URL features dictionary for ML model training/inference",
)
async def extract_features(payload: UrlAnalysisRequest) -> UrlLexicalFeatures:
    """Extract raw structured features from URL for machine learning model pipelines."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    return analyzer.extract_features(payload.url)
