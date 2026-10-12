"""Destination web capture endpoints for dataset samples."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.schemas.capture_schema import WebpageCapture
from app.schemas.pipeline_schema import ApiErrorResponse
from app.services.capture_service import WebCaptureService

router = APIRouter(prefix="/api/v1/dataset", tags=["web capture"])

_ERRORS = {status: {"model": ApiErrorResponse} for status in (400, 404, 422, 500, 503)}


class CaptureRequest(BaseModel):
    urls: list[str] | None = Field(default=None, description="Subset of the post's URLs; default: all of them")
    recapture: bool = Field(default=False, description="Capture again even if already captured")
    retry_failed: bool = Field(default=False, description="Retry URLs whose earlier attempt failed")


class SkippedUrl(BaseModel):
    url: str
    reason: str


class CaptureResponse(BaseModel):
    success: bool = True
    sample_id: str
    captures: list[WebpageCapture]
    skipped: list[SkippedUrl]
    destination: dict[str, Any]


class CaptureHistoryResponse(BaseModel):
    sample_id: str
    captures: list[WebpageCapture]


def get_capture_service(request: Request) -> WebCaptureService:
    return request.app.state.capture_service


@router.post("/samples/{sample_id}/capture", response_model=CaptureResponse, responses=_ERRORS)
def capture_sample(
    sample_id: str,
    service: Annotated[WebCaptureService, Depends(get_capture_service)],
    body: CaptureRequest | None = None,
) -> CaptureResponse:
    """Open the post's destination URL(s) in the isolated browser and store screenshots."""
    body = body or CaptureRequest()
    outcome = service.capture_sample(
        sample_id, urls=body.urls, recapture=body.recapture, retry_failed=body.retry_failed
    )
    sample = service.with_destination(service.store.get_sample(outcome.sample_id),
                                      service.captures_for(outcome.sample_id))
    return CaptureResponse(
        sample_id=outcome.sample_id,
        captures=outcome.captures,
        skipped=[SkippedUrl(url=url, reason=reason) for url, reason in outcome.skipped],
        destination=sample.destination.model_dump(mode="json"),
    )


@router.get("/samples/{sample_id}/captures", response_model=CaptureHistoryResponse, responses=_ERRORS)
def capture_history(
    sample_id: str,
    service: Annotated[WebCaptureService, Depends(get_capture_service)],
) -> CaptureHistoryResponse:
    """Every capture attempt recorded for the sample, oldest first."""
    service.store.get_sample(sample_id)
    return CaptureHistoryResponse(sample_id=sample_id, captures=service.captures_for(sample_id))
