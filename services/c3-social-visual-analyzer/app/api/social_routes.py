"""Live social-media post analysis endpoints used by the dashboard."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Form, Request, UploadFile
from pydantic import BaseModel

from app.schemas.pipeline_schema import ApiErrorResponse
from app.services.facebook_fetcher import fetch_facebook_post, is_facebook_url
from app.services.reddit_fetcher import fetch_reddit_post
from app.services.social_analysis_service import PLATFORMS, SocialAnalysisService, model_results

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
