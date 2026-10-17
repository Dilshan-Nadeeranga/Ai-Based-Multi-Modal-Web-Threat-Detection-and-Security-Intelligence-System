"""Live social-media post analysis endpoints used by the dashboard."""

from __future__ import annotations

import io
import json
import logging
import queue
import threading
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.exceptions import ServiceError
from app.schemas.pipeline_schema import ApiErrorResponse
from app.services.facebook_fetcher import fetch_facebook_post, is_facebook_url
from app.services.reddit_fetcher import fetch_reddit_post
from app.services.social_analysis_service import PLATFORMS, SocialAnalysisService, dataset_overview, model_results

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/social", tags=["social-analysis"])

_ERRORS = {status: {"model": ApiErrorResponse} for status in (400, 422, 500, 503)}


def get_social_service(request: Request) -> SocialAnalysisService:
    return request.app.state.social_service


@router.post("/analyze", responses=_ERRORS)
def analyze_post(
    request: Request,
    platform: Annotated[str, Form()] = "other",
    post_text: Annotated[str, Form()] = "",
    embedded_url: Annotated[str, Form()] = "",
    image: Annotated[UploadFile | None, File()] = None,
) -> dict[str, Any]:
    """Run the full multimodal pipeline on one post. Nothing is stored in the dataset."""
    has_image = image is not None and bool(image.filename)
    return get_social_service(request).analyze(
        platform=platform,
        post_text=post_text,
        image_file=image.file if has_image else None,
        image_filename=image.filename if has_image else None,
        embedded_url=embedded_url,
    )


@router.post("/analyze/stream", responses=_ERRORS)
def analyze_post_stream(
    request: Request,
    platform: Annotated[str, Form()] = "other",
    post_text: Annotated[str, Form()] = "",
    embedded_url: Annotated[str, Form()] = "",
    image: Annotated[UploadFile | None, File()] = None,
) -> StreamingResponse:
    """Same pipeline as /analyze, streamed as NDJSON: one {"type": "step"} line per stage, then {"type": "result"}
    (or {"type": "error"})."""
    service = get_social_service(request)
    has_image = image is not None and bool(image.filename)
    # The upload is read now because the request's file is closed once this handler returns.
    image_bytes = image.file.read(service.settings.max_image_size_bytes + 1) if has_image else None
    filename = image.filename if has_image else None
    events: queue.Queue[dict | None] = queue.Queue()

    def work() -> None:
        try:
            result = service.analyze(
                platform=platform, post_text=post_text, embedded_url=embedded_url, image_filename=filename,
                image_file=io.BytesIO(image_bytes) if image_bytes is not None else None,
                on_step=lambda step: events.put({"type": "step", "step": step}),
            )
            events.put({"type": "result", "result": result})
        except ServiceError as exc:
            events.put({"type": "error", "error": {"code": exc.code, "message": exc.message, "status": exc.status_code}})
        except Exception:  # noqa: BLE001 - reported to the client as a generic error line
            logger.exception("Streaming analysis failed")
            events.put({"type": "error", "error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred.",
                                                   "status": 500}})
        finally:
            events.put(None)

    threading.Thread(target=work, name="c3-social-analyze", daemon=True).start()

    def stream():
        while (event := events.get()) is not None:
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson", headers={"Cache-Control": "no-cache"})


class FetchPostRequest(BaseModel):
    url: str


@router.post("/fetch-post", responses={status: {"model": ApiErrorResponse} for status in (400, 422, 502)})
def fetch_post(request: Request, body: FetchPostRequest) -> dict[str, Any]:
    """Extract post text, embedded URL and image from a public Reddit or Facebook post URL."""
    settings = get_social_service(request).settings
    if is_facebook_url(body.url):
        return fetch_facebook_post(body.url, settings)
    return fetch_reddit_post(body.url, settings)


@router.get("/platforms")
def platforms() -> dict[str, Any]:
    return {"platforms": list(PLATFORMS)}


@router.get("/model-results")
def get_model_results() -> dict[str, Any]:
    """Saved evaluation metrics of the C3 baselines."""
    return model_results()


@router.get("/datasets")
def get_datasets() -> dict[str, Any]:
    """Summaries of the brand, logo-detector and model-training datasets (read-only)."""
    return dataset_overview()
