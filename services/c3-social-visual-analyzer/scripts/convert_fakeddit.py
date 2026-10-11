"""Convert a balanced subset of Fakeddit (multimodal_only_samples) into evidence folders.

Fakeddit (Nakamura et al., LREC 2020) labels Reddit image posts for
misinformation. Labels come from the subreddit (distant supervision), so they
are imported as ``provisional``. Fakeddit has no scam annotation: the scam task
is written as ``not_annotated`` and never guessed.

``6_way_label`` values (checked against the subreddits in the TSV files):
0 real, 1 satire/parody, 2 false connection, 3 imposter content,
4 manipulated content, 5 misleading content. ``2_way_label``: 1 real, 0 fake.

Each selected row becomes ``<out>/fakeddit/real|fake/FKD_<id>/`` holding
``post_info.txt``, ``caption.txt`` (the post title) and ``post1.<ext>``.
Images come from ``--images-dir`` (files named ``<id>.jpg`` as produced by the
official image archive / image_downloader.py) or, with ``--download-images``,
from the row's own ``image_url`` for the selected rows only. Reddit usernames,
comments and scores are never written. Existing folders are never overwritten.

    python scripts/convert_fakeddit.py "D:\\Reasearch\\Datasets\\Fakeddits\\multimodal_only_samples" ^
        "D:\\Reasearch\\ScamTrace_Evidence" --download-images --per-category 20
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from _bootstrap import setup

from app.schemas.dataset_classes import FAKE_CATEGORIES, MisinfoType

SIX_WAY: dict[str, MisinfoType] = {
    "0": MisinfoType.REAL,
    "1": MisinfoType.SATIRE_PARODY,
    "2": MisinfoType.FALSE_CONNECTION,
    "3": MisinfoType.IMPOSTER_CONTENT,
    "4": MisinfoType.MANIPULATED_CONTENT,
    "5": MisinfoType.MISLEADING_CONTENT,
}
FORMAT_SUFFIX = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9]{1,20}$")
FOLDER_PREFIX = "FKD_"
MIN_SIDE = 64
USER_AGENT = "ScamTrace-dataset-prep/0.1 (academic research; Fakeddit image fetch)"


@dataclass(frozen=True)
class Row:
    post_id: str
    title: str
    image_url: str
    subreddit: str
    two_way: str
    three_way: str
    six_way: str

    @property
    def misinfo_type(self) -> MisinfoType:
        return SIX_WAY[self.six_way]

    @property
    def is_fake(self) -> int:
        return 0 if self.two_way == "1" else 1


def read_rows(path: Path):
    """Yield usable rows (image URL + title + known labels) from one TSV file."""
    csv.field_size_limit(10**8)
    with path.open(encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle, delimiter="\t"):
            post_id = (raw.get("id") or "").strip()
            title = (raw.get("title") or "").strip()
            url = (raw.get("image_url") or "").strip()
            six = (raw.get("6_way_label") or "").strip()
            two = (raw.get("2_way_label") or "").strip()
            if not (ID_PATTERN.fullmatch(post_id) and title and six in SIX_WAY and two in ("0", "1")):
                continue
            if not url.lower().startswith(("http://", "https://")):
                continue
            if (SIX_WAY[six] is MisinfoType.REAL) != (two == "1"):
                continue
            yield Row(post_id, title, url, (raw.get("subreddit") or "").strip(),
                      two, (raw.get("3_way_label") or "").strip(), six)


def sample_candidates(rows, wanted: dict[MisinfoType, int], seed: int, spare: int = 4) -> dict[MisinfoType, list[Row]]:
    """Reservoir-sample ``wanted * spare`` rows per category in a single pass."""
    rng = random.Random(seed)
    capacity = {category: count * spare for category, count in wanted.items()}
    reservoirs: dict[MisinfoType, list[Row]] = {category: [] for category in wanted}
    seen: dict[MisinfoType, int] = {category: 0 for category in wanted}
    ids: set[str] = set()
    for row in rows:
        category = row.misinfo_type
        if category not in wanted or row.post_id in ids:
            continue
        ids.add(row.post_id)
        seen[category] += 1
        bucket = reservoirs[category]
        if len(bucket) < capacity[category]:
            bucket.append(row)
        else:
            slot = rng.randrange(seen[category])
            if slot < capacity[category]:
                bucket[slot] = row
    for bucket in reservoirs.values():
        rng.shuffle(bucket)
    return reservoirs


def existing_counts(out: Path) -> dict[MisinfoType, int]:
    """Count Fakeddit folders already in ``out`` per category, so a larger rerun only tops up."""
    counts: dict[MisinfoType, int] = {}
    for info in out.glob(f"*/{FOLDER_PREFIX}*/post_info.txt"):
        for line in info.read_text(encoding="utf-8").splitlines():
            if line.startswith("misinfo_type:"):
                try:
                    category = MisinfoType(line.split(":", 1)[1].strip())
                except ValueError:
                    break
                counts[category] = counts.get(category, 0) + 1
                break
    return counts


def fetch_image(url: str, max_bytes: int, timeout: float) -> tuple[bytes, str]:
    """Download one image; returns (bytes, final URL). Raises OSError on any failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - http(s) checked
            data = response.read(max_bytes + 1)
            final_url = response.geturl()
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        raise OSError(str(exc)) from exc
    if len(data) > max_bytes:
        raise OSError("image larger than the size limit")
    return data, final_url


def check_image(data: bytes) -> str:
    """Return the file suffix for real JPEG/PNG/WEBP data of a useful size, else raise ValueError."""
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            fmt, (width, height) = image.format, image.size
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise ValueError("not a readable image") from exc
    if fmt not in FORMAT_SUFFIX:
        raise ValueError(f"unsupported format {fmt}")
    if min(width, height) < MIN_SIDE:
        raise ValueError(f"image too small ({width}x{height})")
    return FORMAT_SUFFIX[fmt]


def local_image(images_dir: Path, post_id: str) -> bytes | None:
    for suffix in (".jpg", ".jpeg", ".png", ".webp"):
        candidate = images_dir / f"{post_id}{suffix}"
        if candidate.is_file():
            return candidate.read_bytes()
    return None


def post_info(row: Row, split: str) -> str:
    lines = [
        "# Generated by scripts/convert_fakeddit.py - Fakeddit public dataset row",
        "# Misinformation label from the subreddit (distant supervision) -> provisional.",
        "# Fakeddit has no scam annotation, so the scam task is not_annotated.",
        "platform: reddit",
        "is_scam:",
        "scam_type: unknown",
        "label_status: not_annotated",
        f"is_fake: {row.is_fake}",
        f"misinfo_type: {row.misinfo_type.value}",
        "misinfo_label_status: provisional",
        f"misinfo_source_label: fakeddit_2way={row.two_way};3way={row.three_way};6way={row.six_way}",
        "urls:",
        "collection_method: public_dataset",
        f"source_dataset: Fakeddit v2.0 multimodal_only_samples ({split})",
        f"source_reference: {row.post_id}",
        f"notes: Fakeddit label via subreddit r/{row.subreddit}",
    ]
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert a balanced Fakeddit subset into evidence folders.")
    parser.add_argument("tsv_dir", type=Path, help="Folder with multimodal_<split>.tsv files")
    parser.add_argument("out", type=Path, help="Evidence folder (fakeddit/real and fakeddit/fake are created)")
    parser.add_argument("--split", default="train", choices=["train", "validate", "test_public"])
    parser.add_argument("--per-category", type=int, default=20,
                        help="Posts per fake category (5 categories); the same total of real posts is added")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for a reproducible subset")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--images-dir", type=Path, help="Folder with downloaded Fakeddit images named <id>.jpg")
    source.add_argument("--download-images", action="store_true",
                        help="Fetch each selected row's image_url (selected rows only)")
    parser.add_argument("--max-image-mb", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=20.0, help="Seconds per image download")
    parser.add_argument("--delay", type=float, default=0.3, help="Pause between downloads, in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show INFO logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    setup(args.verbose)
    tsv = args.tsv_dir / f"multimodal_{args.split}.tsv"
    if not tsv.is_file():
        print(f"ERROR: not found: {tsv}", file=sys.stderr)
        return 2
    if args.per_category < 1:
        print("ERROR: --per-category must be at least 1", file=sys.stderr)
        return 2
    if args.images_dir is not None and not args.images_dir.is_dir():
        print(f"ERROR: --images-dir not found: {args.images_dir}", file=sys.stderr)
        return 2

    fake_types = sorted(FAKE_CATEGORIES, key=lambda m: m.value)
    wanted = {category: args.per_category for category in fake_types}
    wanted[MisinfoType.REAL] = args.per_category * len(fake_types)
    candidates = sample_candidates(read_rows(tsv), wanted, args.seed)

    out = args.out.expanduser().resolve() / "fakeddit"
    max_bytes = int(args.max_image_mb * 1024 * 1024)
    failed_total = 0
    on_disk = existing_counts(out)
    for category in [MisinfoType.REAL, *fake_types]:
        created = failed = 0
        existing = on_disk.get(category, 0)
        for row in candidates[category]:
            if created + existing >= wanted[category]:
                break
            folder = out / ("real" if row.is_fake == 0 else "fake") / f"{FOLDER_PREFIX}{row.post_id}"
            if folder.exists():
                continue
            try:
                if args.images_dir is not None:
                    data = local_image(args.images_dir, row.post_id)
                    if data is None:
                        raise ValueError("image file not in --images-dir")
                else:
                    data, final_url = fetch_image(row.image_url, max_bytes, args.timeout)
                    if "removed" in final_url.rsplit("/", 1)[-1].lower():
                        raise ValueError("image was removed by the host")
                    time.sleep(args.delay)
                suffix = check_image(data)
            except (OSError, ValueError) as exc:
                failed += 1
                if args.verbose:
                    print(f"  skip {row.post_id}: {exc}")
                continue
            folder.mkdir(parents=True)
            (folder / f"post1{suffix}").write_bytes(data)
            (folder / "caption.txt").write_text(row.title + "\n", encoding="utf-8")
            (folder / "post_info.txt").write_text(post_info(row, args.split), encoding="utf-8")
            created += 1
        failed_total += failed
        short = wanted[category] - created - existing
        print(f"{category.value:20}: {created} new, {existing} already present, {failed} skipped (no usable image)"
              + (f", {short} short of {wanted[category]}" if short > 0 else ""))
    print(f"\nWritten to {out}\nNext: python scripts/import_evidence.py \"{args.out}\" --dry-run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
