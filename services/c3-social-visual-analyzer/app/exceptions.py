"""Controlled exceptions raised by the service.

Every exception carries a stable ``code``, a client-safe ``message`` (never
containing filesystem paths or tracebacks) and an HTTP status.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for all controlled service errors."""

    code: str = "INTERNAL_ERROR"
    status_code: int = 500
    default_message: str = "An internal error occurred."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class InvalidSampleIdError(ServiceError):
    code = "INVALID_SAMPLE_ID"
    status_code = 400
    default_message = (
        "sample_id must start with a letter and contain only letters, digits, "
        "'_' or '-' (max 64 characters), e.g. SCAM_0001."
    )


class SampleAlreadyExistsError(ServiceError):
    code = "SAMPLE_ID_EXISTS"
    status_code = 409
    default_message = "A processed sample with this sample_id already exists."


class StorageError(ServiceError):
    code = "STORAGE_ERROR"
    status_code = 500
    default_message = "Failed to read or write service storage."


class HashDatabaseError(ServiceError):
    code = "HASH_DATABASE_ERROR"
    status_code = 500
    default_message = "The image hash database is unreadable or malformed."


class AnnotationStorageError(ServiceError):
    code = "ANNOTATION_STORAGE_ERROR"
    status_code = 500
    default_message = "The annotation dataset storage is unreadable or malformed."


class ImageProcessingError(ServiceError):
    code = "IMAGE_PROCESSING_FAILED"
    status_code = 422
    default_message = "The image passed validation but could not be processed."


class OcrEngineUnavailableError(ServiceError):
    code = "OCR_ENGINE_UNAVAILABLE"
    status_code = 503
    default_message = (
        "The OCR engine (Tesseract) is not installed or not reachable. "
        "Install Tesseract or set TESSERACT_CMD."
    )


class OcrLanguageUnavailableError(ServiceError):
    code = "OCR_LANGUAGE_UNAVAILABLE"
    status_code = 503
    default_message = "None of the requested OCR languages, nor the fallback language, are installed."


class OcrExecutionError(ServiceError):
    code = "OCR_FAILED"
    status_code = 500
    default_message = "OCR execution failed."


# ---------------------------------------------------------------- dataset


class InvalidDatasetSampleIdError(ServiceError):
    code = "INVALID_SAMPLE_ID"
    status_code = 400
    default_message = "Dataset sample_id must look like SVT_000001 (SVT_ + six digits, not 000000)."


class DatasetValidationError(ServiceError):
    code = "DATASET_VALIDATION_ERROR"
    status_code = 422
    default_message = "The dataset sample is invalid."


class SampleNotFoundError(ServiceError):
    code = "SAMPLE_NOT_FOUND"
    status_code = 404
    default_message = "No dataset sample with this sample_id exists."


class SourceImageNotFoundError(ServiceError):
    code = "SOURCE_IMAGE_NOT_FOUND"
    status_code = 400
    default_message = "A source image file does not exist or is not a regular file."


class UnsupportedImageError(ServiceError):
    code = "UNSUPPORTED_IMAGE"
    status_code = 415
    default_message = "An image is corrupted or is not a supported JPEG, PNG or WebP file."


class SyntheticSampleNotAllowedError(ServiceError):
    code = "SYNTHETIC_NOT_ALLOWED"
    status_code = 400
    default_message = (
        "collection_method 'synthetic_test' is refused for the research dataset. "
        "Use an isolated DATA_DIR with DATASET_ALLOW_SYNTHETIC=true for tests or demos."
    )


class DatasetLockError(ServiceError):
    code = "DATASET_BUSY"
    status_code = 503
    default_message = "The dataset is locked by another writer. Try again shortly."


# ---------------------------------------------------------------- web capture


class WebCaptureDisabledError(ServiceError):
    code = "WEB_CAPTURE_DISABLED"
    status_code = 503
    default_message = "Destination web capture is disabled (WEB_CAPTURE_ENABLED=false)."


class BrowserUnavailableError(ServiceError):
    code = "BROWSER_UNAVAILABLE"
    status_code = 503
    default_message = (
        "The capture browser is not available. Install it with: "
        "pip install -r requirements.txt  and  python -m playwright install chromium"
    )
