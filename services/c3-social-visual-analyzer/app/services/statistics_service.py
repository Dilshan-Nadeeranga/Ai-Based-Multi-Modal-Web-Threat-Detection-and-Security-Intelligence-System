"""Dataset statistics computed from the real ``dataset_metadata.jsonl``.

Nothing here is hard-coded: every number is counted from the current records.
``synthetic_test`` samples are excluded unless explicitly requested so demo or
test data never inflate research figures.
"""

from __future__ import annotations

import logging
from collections import Counter

from pydantic import BaseModel, ValidationError

from app.config import Settings
from app.schemas.dataset_classes import (
    CollectionMethod,
    IsFake,
    IsScam,
    LabelStatus,
    MisinfoType,
    Platform,
    ScamType,
)
from app.schemas.dataset_schema import DatasetSample, utc_now
from app.services.metadata_service import MetadataStore
from app.utils.file_utils import atomic_write_json

logger = logging.getLogger(__name__)


class BinaryLabelCounts(BaseModel):
    legitimate: int = 0
    scam: int = 0
    undecided: int = 0
    not_annotated: int = 0


class ClassBalance(BaseModel):
    """Percentages over samples whose binary label is decided."""

    legitimate_percent: float = 0.0
    scam_percent: float = 0.0


class MisinformationLabelCounts(BaseModel):
    real: int = 0
    fake: int = 0
    undecided: int = 0
    not_annotated: int = 0


class MisinformationBalance(BaseModel):
    """Percentages over samples whose misinformation label is decided."""

    real_percent: float = 0.0
    fake_percent: float = 0.0


class DatasetStatistics(BaseModel):
    dataset_version: str
    generated_at: str
    source_file: str
    includes_synthetic: bool
    total_samples: int
    excluded_synthetic_samples: int
    skipped_invalid_records: int
    malformed_lines: int
    binary_labels: BinaryLabelCounts
    class_balance: ClassBalance
    class_distribution: dict[str, int]
    misinformation_labels: MisinformationLabelCounts
    misinformation_balance: MisinformationBalance
    misinformation_type_distribution: dict[str, int]
    misinformation_label_status: dict[str, int]
    platform_distribution: dict[str, int]
    collection_method_distribution: dict[str, int]
    label_status: dict[str, int]
    dataset_version_distribution: dict[str, int]
    total_images: int
    total_embedded_urls: int
    samples_with_text: int
    samples_with_images: int
    samples_without_images: int
    samples_with_multiple_images: int
    samples_with_urls: int
    samples_without_urls: int
    samples_with_multiple_urls: int
    samples_with_claimed_brand: int


def _zero_filled(counter: Counter[str], keys: list[str]) -> dict[str, int]:
    return {key: counter.get(key, 0) for key in keys}


def _percent(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 2) if whole else 0.0


def compute_statistics(
    samples: list[DatasetSample],
    dataset_version: str,
    *,
    include_synthetic: bool = False,
    skipped_invalid_records: int = 0,
    malformed_lines: int = 0,
) -> DatasetStatistics:
    """Aggregate counts for ``samples`` (pure function, easy to test)."""
    counted = [s for s in samples if include_synthetic or not s.is_synthetic]
    excluded = len(samples) - len(counted)

    scam_labelled = [s for s in counted if s.labels.scam_annotated]
    misinfo_labelled = [s for s in counted if s.labels.misinformation.annotated]

    binary = BinaryLabelCounts(
        legitimate=sum(1 for s in scam_labelled if s.labels.is_scam is IsScam.LEGITIMATE),
        scam=sum(1 for s in scam_labelled if s.labels.is_scam is IsScam.SCAM),
        undecided=sum(1 for s in scam_labelled if s.labels.is_scam is None),
        not_annotated=len(counted) - len(scam_labelled),
    )
    decided = binary.legitimate + binary.scam
    misinfo = MisinformationLabelCounts(
        real=sum(1 for s in misinfo_labelled if s.labels.misinformation.is_fake is IsFake.REAL),
        fake=sum(1 for s in misinfo_labelled if s.labels.misinformation.is_fake is IsFake.FAKE),
        undecided=sum(1 for s in misinfo_labelled if s.labels.misinformation.is_fake is None),
        not_annotated=len(counted) - len(misinfo_labelled),
    )
    misinfo_decided = misinfo.real + misinfo.fake
    image_counts = [len(s.post.images) for s in counted]
    url_counts = [len(s.post.embedded_urls) for s in counted]

    return DatasetStatistics(
        dataset_version=dataset_version,
        generated_at=utc_now().isoformat().replace("+00:00", "Z"),
        source_file="data/annotations/dataset_metadata.jsonl",
        includes_synthetic=include_synthetic,
        total_samples=len(counted),
        excluded_synthetic_samples=excluded,
        skipped_invalid_records=skipped_invalid_records,
        malformed_lines=malformed_lines,
        binary_labels=binary,
        class_balance=ClassBalance(
            legitimate_percent=_percent(binary.legitimate, decided),
            scam_percent=_percent(binary.scam, decided),
        ),
        class_distribution=_zero_filled(
            Counter(s.labels.scam_type.value for s in scam_labelled), [m.value for m in ScamType]
        ),
        misinformation_labels=misinfo,
        misinformation_balance=MisinformationBalance(
            real_percent=_percent(misinfo.real, misinfo_decided),
            fake_percent=_percent(misinfo.fake, misinfo_decided),
        ),
        misinformation_type_distribution=_zero_filled(
            Counter(s.labels.misinformation.misinfo_type.value for s in misinfo_labelled),
            [m.value for m in MisinfoType],
        ),
        misinformation_label_status=_zero_filled(
            Counter(s.labels.misinformation.label_status.value for s in counted), [m.value for m in LabelStatus]
        ),
        platform_distribution=_zero_filled(
            Counter(s.source.platform.value for s in counted), [m.value for m in Platform]
        ),
        collection_method_distribution=_zero_filled(
            Counter(s.source.collection_method.value for s in counted), [m.value for m in CollectionMethod]
        ),
        label_status=_zero_filled(
            Counter(s.labels.label_status.value for s in counted), [m.value for m in LabelStatus]
        ),
        dataset_version_distribution=dict(sorted(Counter(s.dataset_version for s in counted).items())),
        total_images=sum(image_counts),
        total_embedded_urls=sum(url_counts),
        samples_with_text=sum(1 for s in counted if s.post.text),
        samples_with_images=sum(1 for n in image_counts if n > 0),
        samples_without_images=sum(1 for n in image_counts if n == 0),
        samples_with_multiple_images=sum(1 for n in image_counts if n > 1),
        samples_with_urls=sum(1 for n in url_counts if n > 0),
        samples_without_urls=sum(1 for n in url_counts if n == 0),
        samples_with_multiple_urls=sum(1 for n in url_counts if n > 1),
        samples_with_claimed_brand=sum(1 for s in counted if s.brand.claimed_brand),
    )


class StatisticsService:
    """Reads the metadata file, computes statistics and writes them to disk."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = MetadataStore(settings.dataset_metadata_path, settings.labels_path)

    def compute(self, include_synthetic: bool = False) -> DatasetStatistics:
        metadata = self.store.read_metadata()
        samples: list[DatasetSample] = []
        invalid = 0
        for line, row in metadata.rows:
            try:
                samples.append(DatasetSample.model_validate(row))
            except ValidationError:
                invalid += 1
                logger.warning("Statistics skipped invalid record at line %d (run validate_dataset.py)", line)
        seen: set[str] = set()
        unique: list[DatasetSample] = []
        for sample in samples:
            if sample.sample_id in seen:
                invalid += 1
                logger.warning("Statistics skipped duplicate sample_id %s", sample.sample_id)
                continue
            seen.add(sample.sample_id)
            unique.append(sample)
        return compute_statistics(
            unique,
            self.settings.dataset_version,
            include_synthetic=include_synthetic,
            skipped_invalid_records=invalid,
            malformed_lines=len(metadata.issues),
        )

    def generate(self, include_synthetic: bool = False) -> DatasetStatistics:
        """Compute and write ``data/statistics/dataset_statistics.json``."""
        stats = self.compute(include_synthetic=include_synthetic)
        self.settings.statistics_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.settings.dataset_statistics_path, stats.model_dump(mode="json"))
        logger.info(
            "Statistics generated: %d samples (%d legitimate, %d scam)",
            stats.total_samples,
            stats.binary_labels.legitimate,
            stats.binary_labels.scam,
        )
        return stats
