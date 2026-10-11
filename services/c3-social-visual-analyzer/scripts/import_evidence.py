"""Import manually collected posts from an evidence folder into the dataset.

Expected layout (one folder per post; folder names are free):

    ScamTrace_Evidence/
        legit/001/   post_info.txt  caption.txt  post1.png ...
        scam/001/    post_info.txt  caption.txt  post1.png post2.jpg ...

* ``post_info.txt`` holds ``key: value`` lines (``#`` starts a comment):
  platform, is_scam, scam_type, label_status, urls, source_url, claimed_brand,
  notes, collection_method, collected_at, source_dataset, source_reference.
* ``caption.txt`` (optional) holds the post text, UTF-8.
* Images (.jpg/.jpeg/.png/.webp) are added in file-name order.
* A folder with neither caption nor images is treated as "not filled in yet".
* After a successful import ``imported.txt`` is written with the new sample ID,
  and that folder is skipped on later runs.
* Folders under ``legit/`` must have ``is_scam: 0``; folders under ``scam/``
  must have ``is_scam: 1`` (or empty while undecided).

    python scripts/import_evidence.py "E:\\ScamTrace_Evidence" --dry-run
    python scripts/import_evidence.py "E:\\ScamTrace_Evidence"

``--write-templates`` creates a blank ``post_info.txt``/``caption.txt`` in every
post folder that has none.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from _bootstrap import SERVICE_ROOT, load_settings, setup

from pydantic import ValidationError

from app.exceptions import ServiceError
from app.schemas.dataset_classes import LabelStatus
from app.services.dataset_service import DatasetService, NewSampleRequest, format_validation_error, build_request
from app.utils.file_utils import utc_now_iso

INFO_FILE = "post_info.txt"
CAPTION_FILE = "caption.txt"
IMPORTED_FILE = "imported.txt"
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp"}

FIELD_MAP = {
    "platform": "platform",
    "is_scam": "is_scam",
    "scam_type": "scam_type",
    "label_status": "label_status",
    "urls": "embedded_urls",
    "source_url": "source_url",
    "claimed_brand": "claimed_brand",
    "notes": "label_notes",
    "collection_method": "collection_method",
    "collected_at": "collected_at",
    "source_dataset": "source_dataset",
    "source_reference": "source_reference",
    "is_fake": "is_fake",
    "misinfo_type": "misinfo_type",
    "misinfo_label_status": "misinfo_label_status",
    "misinfo_source_label": "misinfo_source_label",
}
BINARY_FIELDS = ("is_scam", "is_fake")

LEGIT_TEMPLATE = """\
# ScamTrace post info - fill in, save, then run scripts/import_evidence.py
# Lines starting with # are ignored. Leave a value empty if unknown.
# Put the post caption in caption.txt and the screenshots (post1.png, post2.png ...) in this folder.

# facebook | instagram | x | tiktok | youtube | linkedin | telegram | whatsapp | website | other | unknown
platform: facebook

# 0 = legitimate, 1 = scam, empty = not sure (then scam_type: unknown, label_status: needs_review)
is_scam: 0

# legitimate | phishing | brand_impersonation | financial_scam | data_theft | malware | browser_abuse | other_scam | unknown
scam_type: legitimate

# verified | provisional | needs_review
label_status: verified

# Links shown in the post ("Copy link address" - never open scam links). Several: separate with spaces.
urls:

# Public address of the post itself (optional)
source_url:

# Brand the post presents itself as, e.g. Commercial Bank (optional)
claimed_brand:

# Why you chose this label (optional)
notes:

# Optional fake-news label (separate task): remove the leading # of the three keys and fill them in.
# 0 = real, 1 = fake
#is_fake:
# real | satire_parody | misleading_content | imposter_content | false_connection | manipulated_content | unknown
#misinfo_type:
# verified | provisional | needs_review
#misinfo_label_status:
"""

SCAM_TEMPLATE = (
    LEGIT_TEMPLATE
    .replace("is_scam: 0\n", "is_scam: 1\n")
    .replace("scam_type: legitimate\n", "scam_type: phishing\n")
    .replace("label_status: verified\n", "label_status: provisional\n")
)


class EvidenceError(Exception):
    """A post folder cannot be imported as written."""


def _natural_key(name: str) -> list[object]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", name)]


def parse_post_info(path: Path) -> dict[str, object]:
    fields: dict[str, object] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise EvidenceError(f"cannot read {INFO_FILE} as UTF-8: {exc}") from exc
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        key = key.strip().lower()
        if not sep or key not in FIELD_MAP:
            raise EvidenceError(f"{INFO_FILE} line {number}: unknown entry {line[:40]!r}")
        value = value.strip()
        fields[FIELD_MAP[key]] = value or None
    for name in BINARY_FIELDS:
        value = fields.get(name)
        if value is not None and value not in ("0", "1"):
            raise EvidenceError(f"{name} must be 0, 1 or empty, got {value!r}")
        fields[name] = None if value is None else int(value)
    return fields


def _category(folder: Path, root: Path) -> str | None:
    top = folder.relative_to(root).parts[0].lower()
    if top.startswith("legit"):
        return "legit"
    if top.startswith("scam"):
        return "scam"
    return None


def load_post(folder: Path, root: Path) -> tuple[NewSampleRequest, list[Path]] | None:
    """Return (request, images), or None if the folder is still empty."""
    fields = parse_post_info(folder / INFO_FILE)
    caption_path = folder / CAPTION_FILE
    caption = None
    if caption_path.is_file():
        try:
            caption = caption_path.read_text(encoding="utf-8-sig").strip() or None
        except (OSError, UnicodeDecodeError) as exc:
            raise EvidenceError(f"cannot read {CAPTION_FILE} as UTF-8: {exc}") from exc
    images = sorted(
        (p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES),
        key=lambda p: _natural_key(p.name),
    )
    if caption is None and not images:
        return None

    category = _category(folder, root)
    if category == "legit" and fields["is_scam"] != 0:
        raise EvidenceError("folder is under legit/ but is_scam is not 0")
    if category == "scam" and fields["is_scam"] == 0:
        raise EvidenceError("folder is under scam/ but is_scam is 0")
    for required in ("platform", "scam_type", "label_status"):
        if not fields.get(required):
            raise EvidenceError(f"{INFO_FILE} is missing a value for {required}")
    request = build_request(post_text=caption, **fields)
    try:
        request.labels()
    except ValidationError as exc:
        raise EvidenceError("Invalid label: " + format_validation_error(exc)) from exc
    return request, images


def write_templates(root: Path) -> int:
    created = 0
    for category, template in (("legit", LEGIT_TEMPLATE), ("scam", SCAM_TEMPLATE)):
        base = root / category
        if not base.is_dir():
            continue
        for folder in sorted(p for p in base.iterdir() if p.is_dir()):
            info = folder / INFO_FILE
            if not info.exists():
                info.write_text(template, encoding="utf-8")
                created += 1
            caption = folder / CAPTION_FILE
            if not caption.exists():
                caption.write_text("", encoding="utf-8")
    return created


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import post folders (post_info.txt + caption + images).")
    parser.add_argument("evidence_dir", type=Path, help="Folder containing legit/ and scam/ post folders")
    parser.add_argument("--dry-run", action="store_true", help="Check every folder without adding anything")
    parser.add_argument("--write-templates", action="store_true",
                        help="Create blank post_info.txt/caption.txt in legit/*/ and scam/*/ folders, then exit")
    parser.add_argument("--data-dir", help="Alternative data directory (e.g. a demo/test copy)")
    parser.add_argument("--allow-synthetic", action="store_true",
                        help="Permit collection_method synthetic_test (only with a non-default --data-dir)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show INFO logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    setup(args.verbose)
    root = args.evidence_dir.expanduser().resolve()
    if not root.is_dir():
        print(f"ERROR: evidence folder not found: {root}", file=sys.stderr)
        return 2

    if args.write_templates:
        print(f"Created {write_templates(root)} post_info.txt template(s) under {root}")
        return 0

    default_data_dir = (SERVICE_ROOT / "data").resolve()
    settings = load_settings(args.data_dir, **({"dataset_allow_synthetic": True} if args.allow_synthetic else {}))
    if args.allow_synthetic and settings.data_dir == default_data_dir:
        print("ERROR: --allow-synthetic requires --data-dir pointing outside the research data/ folder.",
              file=sys.stderr)
        return 2
    service = DatasetService(settings)

    counts = {"imported": 0, "ready": 0, "already": 0, "empty": 0, "failed": 0}
    post_files = sorted(root.rglob(INFO_FILE), key=lambda p: [_natural_key(x) for x in p.relative_to(root).parts])
    for info in post_files:
        folder = info.parent
        label = folder.relative_to(root).as_posix()
        if (folder / IMPORTED_FILE).exists():
            counts["already"] += 1
            print(f"SKIP   {label}: already imported ({(folder / IMPORTED_FILE).read_text(encoding='utf-8').split()[0]})")
            continue
        try:
            post = load_post(folder, root)
            if post is None:
                counts["empty"] += 1
                print(f"EMPTY  {label}: no caption or images yet")
                continue
            request, images = post
            if args.dry_run:
                counts["ready"] += 1
                is_scam = None if request.is_scam is None else int(request.is_scam)
                line = (f"READY  {label}: {len(images)} image(s), {len(request.embedded_urls)} url(s), "
                        f"is_scam={is_scam} {request.scam_type.value}/{request.label_status.value}")
                if request.misinfo_label_status is not LabelStatus.NOT_ANNOTATED:
                    is_fake = None if request.is_fake is None else int(request.is_fake)
                    line += (f", is_fake={is_fake} {request.misinfo_type.value}/"
                             f"{request.misinfo_label_status.value}")
                print(line)
                continue
            sample = service.add_sample(request, images=images)
        except EvidenceError as exc:
            counts["failed"] += 1
            print(f"FAIL   {label}: {exc}", file=sys.stderr)
            continue
        except ServiceError as exc:
            counts["failed"] += 1
            print(f"FAIL   {label}: [{exc.code}] {exc.message}", file=sys.stderr)
            continue
        (folder / IMPORTED_FILE).write_text(f"{sample.sample_id}\nimported_at: {utc_now_iso()}\n", encoding="utf-8")
        counts["imported"] += 1
        print(f"ADDED  {label} -> {sample.sample_id} ({len(sample.post.images)} image(s), "
              f"{len(sample.post.embedded_urls)} url(s))")

    done = f"{counts['ready']} ready" if args.dry_run else f"{counts['imported']} imported"
    print(f"\n{done}, {counts['already']} already imported, {counts['empty']} empty, {counts['failed']} failed")
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
