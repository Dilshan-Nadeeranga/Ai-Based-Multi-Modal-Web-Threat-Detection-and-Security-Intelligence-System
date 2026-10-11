"""Add one manually collected social-media post to the dataset.

Examples (run from services/c3-social-visual-analyzer):

    python scripts/add_sample.py --platform facebook \
        --text "Official security awareness post" \
        --image ./legit_01.jpg --url https://www.example.com/security \
        --is-scam 0 --scam-type legitimate --label-status verified

    python scripts/add_sample.py --platform facebook --text-file post.txt \
        --image shot1.png shot2.png --url https://example.invalid/a https://example.invalid/b \
        --is-scam 1 --scam-type brand_impersonation --label-status provisional \
        --claimed-brand ExampleBank

Leave out --is-scam (with --scam-type unknown --label-status needs_review)
when the ground truth is still undecided.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import SERVICE_ROOT, load_settings, setup

from app.exceptions import ServiceError
from app.schemas.dataset_classes import CollectionMethod, LabelStatus, MisinfoType, Platform, ScamType
from app.services.dataset_service import DatasetService, build_request


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Add one social-media post sample to the dataset.")
    parser.add_argument("--platform", required=True, choices=[p.value for p in Platform])
    text = parser.add_mutually_exclusive_group()
    text.add_argument("--text", help="Post text exactly as observed")
    text.add_argument("--text-file", type=Path, help="UTF-8 file containing the post text (best for Sinhala/Tamil)")
    parser.add_argument("--image", action="extend", nargs="+", default=[], type=Path,
                        help="Image file(s) in post order; repeat or list several")
    parser.add_argument("--url", action="extend", nargs="+", default=[],
                        help="Embedded URL(s) in post order; repeat or list several")
    parser.add_argument("--is-scam", type=int, choices=[0, 1], help="0 = legitimate, 1 = scam; omit if undecided")
    parser.add_argument("--scam-type", required=True, choices=[t.value for t in ScamType])
    parser.add_argument("--label-status", required=True, choices=[s.value for s in LabelStatus])
    parser.add_argument("--claimed-brand", help="Brand the post presents itself as (not a class)")
    parser.add_argument("--source-url", help="Public URL of the original post, if appropriate")
    parser.add_argument("--collection-method", default=CollectionMethod.MANUAL.value,
                        choices=[m.value for m in CollectionMethod])
    parser.add_argument("--collected-at", help="ISO-8601 time the post was collected (default: now, UTC)")
    parser.add_argument("--source-dataset", help="Name of the public dataset/archive, if any")
    parser.add_argument("--source-reference", help="Citation or record ID in the source dataset")
    parser.add_argument("--notes", help="Annotator notes explaining the label")
    parser.add_argument("--is-fake", type=int, choices=[0, 1],
                        help="Misinformation task: 0 = real, 1 = fake; omit if not annotated/undecided")
    parser.add_argument("--misinfo-type", default=MisinfoType.UNKNOWN.value, choices=[t.value for t in MisinfoType])
    parser.add_argument("--misinfo-status", default=LabelStatus.NOT_ANNOTATED.value,
                        choices=[s.value for s in LabelStatus], help="Misinformation label status")
    parser.add_argument("--misinfo-source-label", help="Original label in the source dataset, e.g. fakeddit_6way=2")
    parser.add_argument("--sample-id", help="Use a specific free ID such as SVT_000050 (default: next ID)")
    parser.add_argument("--data-dir", help="Alternative data directory (e.g. a demo/test copy)")
    parser.add_argument("--allow-synthetic", action="store_true",
                        help="Permit collection_method synthetic_test (only with a non-default --data-dir)")
    parser.add_argument("--json", action="store_true", help="Print the full created record as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show INFO logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    setup(args.verbose)

    default_data_dir = (SERVICE_ROOT / "data").resolve()
    settings = load_settings(args.data_dir, **({"dataset_allow_synthetic": True} if args.allow_synthetic else {}))
    if args.allow_synthetic and settings.data_dir == default_data_dir:
        print("ERROR: --allow-synthetic requires --data-dir pointing outside the research data/ folder.",
              file=sys.stderr)
        return 2

    try:
        post_text = args.text_file.read_text(encoding="utf-8") if args.text_file else args.text
    except (OSError, UnicodeDecodeError) as exc:
        print(f"ERROR: cannot read --text-file as UTF-8: {exc}", file=sys.stderr)
        return 2

    try:
        request = build_request(
            platform=args.platform,
            post_text=post_text,
            embedded_urls=args.url,
            is_scam=args.is_scam,
            scam_type=args.scam_type,
            label_status=args.label_status,
            claimed_brand=args.claimed_brand,
            source_url=args.source_url,
            collection_method=args.collection_method,
            collected_at=args.collected_at,
            source_dataset=args.source_dataset,
            source_reference=args.source_reference,
            label_notes=args.notes,
            is_fake=args.is_fake,
            misinfo_type=args.misinfo_type,
            misinfo_label_status=args.misinfo_status,
            misinfo_source_label=args.misinfo_source_label,
            sample_id=args.sample_id,
        )
        sample = DatasetService(settings).add_sample(request, images=list(args.image))
    except ServiceError as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1

    labels = sample.labels
    print(f"Created {sample.sample_id}")
    print(f"  platform      : {sample.source.platform.value} ({sample.source.collection_method.value})")
    print(f"  text          : {(sample.post.text or '')[:80]!r}")
    print(f"  images ({len(sample.post.images)})    : {', '.join(sample.post.images) or '-'}")
    print(f"  urls ({len(sample.post.embedded_urls)})      : {', '.join(sample.post.embedded_urls) or '-'}")
    print(f"  labels        : is_scam={None if labels.is_scam is None else int(labels.is_scam)} "
          f"scam_type={labels.scam_type.value} status={labels.label_status.value}")
    misinfo = labels.misinformation
    if misinfo.annotated:
        print(f"  misinformation: is_fake={None if misinfo.is_fake is None else int(misinfo.is_fake)} "
              f"misinfo_type={misinfo.misinfo_type.value} status={misinfo.label_status.value}")
    if args.json:
        print(json.dumps(sample.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
