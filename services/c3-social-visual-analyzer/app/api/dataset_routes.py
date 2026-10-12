"""Dataset ingestion and inspection endpoints (Phase 1 dataset preparation)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api.responses import service_error_response
from app.exceptions import DatasetValidationError, ServiceError
from app.schemas.dataset_classes import allowed_classes
from app.schemas.dataset_schema import DatasetSample
from app.schemas.pipeline_schema import ApiErrorResponse
from app.services.dataset_service import DatasetService, ImageUpload, build_request
from app.services.statistics_service import DatasetStatistics, StatisticsService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dataset", tags=["dataset"])

_ERRORS = {status: {"model": ApiErrorResponse} for status in (400, 404, 409, 415, 422, 500, 503)}


class SampleSummary(BaseModel):
    platform: str
    image_count: int
    url_count: int
    labels: dict[str, Any]


class SampleCreatedResponse(BaseModel):
    success: bool = True
    sample_id: str
    message: str = "Dataset sample created successfully"
    data: SampleSummary
    record: dict[str, Any]


def get_dataset_service(request: Request) -> DatasetService:
    return request.app.state.dataset_service


def get_statistics_service(request: Request) -> StatisticsService:
    return request.app.state.statistics_service


def _parse_binary(value: str | None, field: str, meaning: str) -> int | None:
    if value is None or not value.strip() or value.strip().lower() in {"null", "none"}:
        return None
    if value.strip() in {"0", "1"}:
        return int(value.strip())
    raise DatasetValidationError(f"{field} must be {meaning} or empty when undecided/not annotated.")


def _parse_is_scam(value: str | None) -> int | None:
    return _parse_binary(value, "is_scam", "0 (legitimate), 1 (scam)")


@router.post("/samples", response_model=SampleCreatedResponse, responses=_ERRORS, status_code=201)
def create_sample(
    service: Annotated[DatasetService, Depends(get_dataset_service)],
    platform: Annotated[str, Form()],
    scam_type: Annotated[str, Form()],
    label_status: Annotated[str, Form()],
    post_text: Annotated[str | None, Form()] = None,
    images: Annotated[list[UploadFile] | None, File(description="Post images in order")] = None,
    embedded_urls: Annotated[list[str] | None, Form(description="Repeat the field once per URL")] = None,
    is_scam: Annotated[str | None, Form(description="0, 1, or empty when undecided")] = None,
    claimed_brand: Annotated[str | None, Form()] = None,
    source_url: Annotated[str | None, Form()] = None,
    collection_method: Annotated[str, Form()] = "manual",
    collected_at: Annotated[str | None, Form()] = None,
    source_dataset: Annotated[str | None, Form()] = None,
    source_reference: Annotated[str | None, Form()] = None,
    label_notes: Annotated[str | None, Form()] = None,
    is_fake: Annotated[str | None, Form(description="Misinformation: 0 real, 1 fake, empty if not annotated")] = None,
    misinfo_type: Annotated[str, Form()] = "unknown",
    misinfo_label_status: Annotated[str, Form()] = "not_annotated",
    misinfo_source_label: Annotated[str | None, Form()] = None,
) -> SampleCreatedResponse | JSONResponse:
    """Create one sample linking post text, images and URLs under a new SVT ID."""
    uploads = [upload for upload in (images or []) if upload.filename or upload.size]
    try:
        request = build_request(
            platform=platform,
            post_text=post_text,
            embedded_urls=embedded_urls or [],
            is_scam=_parse_is_scam(is_scam),
            scam_type=scam_type,
            label_status=label_status,
            claimed_brand=claimed_brand,
            source_url=source_url,
            collection_method=collection_method,
            collected_at=collected_at or None,
            source_dataset=source_dataset,
            source_reference=source_reference,
            label_notes=label_notes,
            is_fake=_parse_binary(is_fake, "is_fake", "0 (real), 1 (fake)"),
            misinfo_type=misinfo_type,
            misinfo_label_status=misinfo_label_status,
            misinfo_source_label=misinfo_source_label,
        )
        sample = service.add_sample(request, [ImageUpload(u.file, u.filename) for u in uploads])
    except ServiceError as exc:
        return service_error_response(exc)
    finally:
        for upload in uploads:
            upload.file.close()

    labels = sample.labels
    return SampleCreatedResponse(
        sample_id=sample.sample_id,
        data=SampleSummary(
            platform=sample.source.platform.value,
            image_count=len(sample.post.images),
            url_count=len(sample.post.embedded_urls),
            labels={
                "is_scam": None if labels.is_scam is None else int(labels.is_scam),
                "scam_type": labels.scam_type.value,
                "label_status": labels.label_status.value,
                "is_fake": None if labels.misinformation.is_fake is None else int(labels.misinformation.is_fake),
                "misinfo_type": labels.misinformation.misinfo_type.value,
                "misinfo_label_status": labels.misinformation.label_status.value,
            },
        ),
        record=sample.model_dump(mode="json"),
    )


@router.get("/samples/{sample_id}", responses=_ERRORS)
def get_sample(
    sample_id: str,
    request: Request,
    service: Annotated[DatasetService, Depends(get_dataset_service)],
) -> dict[str, Any]:
    """The sample record; ``destination`` is filled from its latest successful web capture."""
    sample: DatasetSample = service.get_sample(sample_id)
    captures = request.app.state.capture_service
    return captures.with_destination(sample, captures.captures_for(sample.sample_id)).model_dump(mode="json")


@router.get("/statistics", response_model=DatasetStatistics, responses=_ERRORS)
def get_statistics(
    service: Annotated[StatisticsService, Depends(get_statistics_service)],
    include_synthetic: Annotated[bool, Query()] = False,
) -> DatasetStatistics:
    """Statistics computed now from dataset_metadata.jsonl (not written to disk)."""
    return service.compute(include_synthetic=include_synthetic)


@router.get("/classes")
def get_classes() -> dict[str, object]:
    return allowed_classes()
