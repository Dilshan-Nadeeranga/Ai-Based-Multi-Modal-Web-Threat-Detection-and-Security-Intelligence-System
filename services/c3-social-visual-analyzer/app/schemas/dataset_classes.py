"""Controlled vocabularies for the multimodal social-media dataset.

Brands are *not* classes: ``brand.claimed_brand = "PayPal"`` together with
``labels.scam_type = brand_impersonation`` is the correct representation.
See ``docs/dataset_labels.md`` for the annotation guide.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class IsScam(IntEnum):
    """Primary binary ground-truth label."""

    LEGITIMATE = 0
    SCAM = 1


class ScamType(str, Enum):
    """Secondary multiclass label."""

    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    BRAND_IMPERSONATION = "brand_impersonation"
    FINANCIAL_SCAM = "financial_scam"
    DATA_THEFT = "data_theft"
    MALWARE = "malware"
    BROWSER_ABUSE = "browser_abuse"
    OTHER_SCAM = "other_scam"
    UNKNOWN = "unknown"


SCAM_CATEGORIES: frozenset[ScamType] = frozenset(
    {
        ScamType.PHISHING,
        ScamType.BRAND_IMPERSONATION,
        ScamType.FINANCIAL_SCAM,
        ScamType.DATA_THEFT,
        ScamType.MALWARE,
        ScamType.BROWSER_ABUSE,
        ScamType.OTHER_SCAM,
    }
)


class IsFake(IntEnum):
    """Binary misinformation label (separate task from ``is_scam``)."""

    REAL = 0
    FAKE = 1


class MisinfoType(str, Enum):
    """Fine-grained misinformation label (Fakeddit 6-way taxonomy)."""

    REAL = "real"
    SATIRE_PARODY = "satire_parody"
    MISLEADING_CONTENT = "misleading_content"
    IMPOSTER_CONTENT = "imposter_content"
    FALSE_CONNECTION = "false_connection"
    MANIPULATED_CONTENT = "manipulated_content"
    UNKNOWN = "unknown"


FAKE_CATEGORIES: frozenset[MisinfoType] = frozenset(
    {
        MisinfoType.SATIRE_PARODY,
        MisinfoType.MISLEADING_CONTENT,
        MisinfoType.IMPOSTER_CONTENT,
        MisinfoType.FALSE_CONNECTION,
        MisinfoType.MANIPULATED_CONTENT,
    }
)


class LabelStatus(str, Enum):
    """How far a human annotation has been reviewed.

    ``not_annotated`` means the sample was never labelled for that task (e.g. a
    fake-news dataset row has no scam label); it is not a pending review.
    """

    VERIFIED = "verified"
    PROVISIONAL = "provisional"
    NEEDS_REVIEW = "needs_review"
    NOT_ANNOTATED = "not_annotated"


class Platform(str, Enum):
    """Where the post was observed. Never inferred from a URL alone."""

    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    X = "x"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    LINKEDIN = "linkedin"
    TELEGRAM = "telegram"
    WHATSAPP = "whatsapp"
    REDDIT = "reddit"
    WEBSITE = "website"
    OTHER = "other"
    UNKNOWN = "unknown"


class CollectionMethod(str, Enum):
    """How the sample entered the dataset."""

    MANUAL = "manual"
    PUBLIC_DATASET = "public_dataset"
    API = "api"
    RESEARCH_ARCHIVE = "research_archive"
    SYNTHETIC_TEST = "synthetic_test"


def check_label_consistency(
    is_scam: IsScam | None,
    scam_type: ScamType,
    label_status: LabelStatus,
) -> list[str]:
    """Return human-readable violations of the labelling rules (empty = valid).

    Rules:
    * ``is_scam = 0`` requires ``scam_type = legitimate``.
    * ``is_scam = 1`` requires a scam category, or ``unknown`` while unverified.
    * ``is_scam = null`` (binary label undecided) requires ``needs_review`` or
      ``not_annotated`` and ``scam_type = unknown``.
    * ``not_annotated`` requires ``is_scam = null``.
    * ``unknown`` is never allowed on a ``verified`` label.
    """
    problems: list[str] = []

    if is_scam is None:
        if label_status not in (LabelStatus.NEEDS_REVIEW, LabelStatus.NOT_ANNOTATED):
            problems.append("is_scam may only be null when label_status is 'needs_review' or 'not_annotated'")
        if scam_type is not ScamType.UNKNOWN:
            problems.append("scam_type must be 'unknown' when is_scam is null")
        return problems
    if label_status is LabelStatus.NOT_ANNOTATED:
        problems.append("label_status 'not_annotated' requires is_scam to be empty")
        return problems

    if is_scam is IsScam.LEGITIMATE and scam_type is not ScamType.LEGITIMATE:
        problems.append(
            f"is_scam=0 (legitimate) requires scam_type 'legitimate', got '{scam_type.value}'"
        )
    if is_scam is IsScam.SCAM:
        if scam_type is ScamType.LEGITIMATE:
            problems.append("is_scam=1 (scam) cannot use scam_type 'legitimate'")
        elif scam_type is ScamType.UNKNOWN and label_status is LabelStatus.VERIFIED:
            problems.append("a verified scam label needs a specific scam_type, not 'unknown'")
    return problems


def check_misinformation_consistency(
    is_fake: IsFake | None,
    misinfo_type: MisinfoType,
    label_status: LabelStatus,
) -> list[str]:
    """Same rules as :func:`check_label_consistency`, for the misinformation task.

    * ``is_fake = 0`` requires ``misinfo_type = real``.
    * ``is_fake = 1`` requires a fake category, or ``unknown`` while unverified.
    * ``is_fake = null`` requires ``unknown`` with ``needs_review`` or ``not_annotated``.
    """
    problems: list[str] = []

    if is_fake is None:
        if label_status not in (LabelStatus.NEEDS_REVIEW, LabelStatus.NOT_ANNOTATED):
            problems.append("is_fake may only be null when the misinformation label_status is "
                            "'needs_review' or 'not_annotated'")
        if misinfo_type is not MisinfoType.UNKNOWN:
            problems.append("misinfo_type must be 'unknown' when is_fake is null")
        return problems
    if label_status is LabelStatus.NOT_ANNOTATED:
        problems.append("misinformation label_status 'not_annotated' requires is_fake to be empty")
        return problems

    if is_fake is IsFake.REAL and misinfo_type is not MisinfoType.REAL:
        problems.append(f"is_fake=0 (real) requires misinfo_type 'real', got '{misinfo_type.value}'")
    if is_fake is IsFake.FAKE:
        if misinfo_type is MisinfoType.REAL:
            problems.append("is_fake=1 (fake) cannot use misinfo_type 'real'")
        elif misinfo_type is MisinfoType.UNKNOWN and label_status is LabelStatus.VERIFIED:
            problems.append("a verified fake label needs a specific misinfo_type, not 'unknown'")
    return problems


def allowed_classes() -> dict[str, object]:
    """Describe every controlled vocabulary (used by the /classes endpoint)."""
    return {
        "is_scam": {str(member.value): member.name.lower() for member in IsScam},
        "scam_type": [member.value for member in ScamType],
        "scam_categories": sorted(member.value for member in SCAM_CATEGORIES),
        "is_fake": {str(member.value): member.name.lower() for member in IsFake},
        "misinfo_type": [member.value for member in MisinfoType],
        "fake_categories": sorted(member.value for member in FAKE_CATEGORIES),
        "label_status": [member.value for member in LabelStatus],
        "platform": [member.value for member in Platform],
        "collection_method": [member.value for member in CollectionMethod],
    }
