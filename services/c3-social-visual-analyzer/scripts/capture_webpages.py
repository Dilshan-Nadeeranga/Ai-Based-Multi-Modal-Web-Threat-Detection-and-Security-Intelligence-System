"""Capture the destination web pages of dataset samples.

Opens each URL of the selected posts in the isolated headless browser,
follows redirects, records the final URL/domain/title and stores a full-page
screenshot as data/webpage_screenshots/SVT_xxxxxx_web_NN.png. Every attempt
(including blocked or unreachable URLs) is appended to
data/annotations/webpage_captures.jsonl.

    python scripts/capture_webpages.py --sample-id SVT_000001
    python scripts/capture_webpages.py --all --is-scam 0 --dry-run
    python scripts/capture_webpages.py --source-dataset Phish360 --is-scam 0 --limit 20 --delay 2
    python scripts/capture_webpages.py --all --is-scam 1 --allow-scam-urls      # only inside a VM / Windows Sandbox
    python scripts/capture_webpages.py --all --retry-failed

Samples labelled as scams are only opened with --allow-scam-urls: run those
from a disposable VM or Windows Sandbox, never from your normal machine.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from _bootstrap import load_settings, setup

from app.exceptions import ServiceError
from app.schemas.capture_schema import CaptureStatus, WebpageCapture
from app.schemas.dataset_classes import IsScam, Platform
from app.schemas.dataset_schema import DatasetSample
from app.services.capture_service import WebCaptureService, candidate_urls
from app.utils.url_utils import unwrap_link


def _select(service: WebCaptureService, args: argparse.Namespace) -> list[DatasetSample]:
    samples = service.load_samples()
    if args.sample_id:
        wanted = {sid.strip().upper() for sid in args.sample_id}
        missing = wanted - {s.sample_id for s in samples}
        if missing:
            raise SystemExit(f"Unknown sample_id(s): {', '.join(sorted(missing))}")
        samples = [s for s in samples if s.sample_id in wanted]
    if args.source_dataset:
        needle = args.source_dataset.lower()
        samples = [s for s in samples if s.source.source_dataset and needle in s.source.source_dataset.lower()]
    if args.platform:
        samples = [s for s in samples if s.source.platform is Platform(args.platform)]
    if args.is_scam is not None:
        samples = [s for s in samples if s.labels.is_scam is IsScam(args.is_scam)]
    if not args.include_synthetic and not args.sample_id:
        samples = [s for s in samples if not s.is_synthetic]
    samples = [s for s in samples if candidate_urls(s)]
    return samples[: args.limit] if args.limit else samples


def _dry_run(service: WebCaptureService, samples: list[DatasetSample], args: argparse.Namespace) -> None:
    history = service.captures_by_sample()
    verdicts: Counter[str] = Counter()
    for sample in samples:
        todo, skipped = service.plan(sample, None, history.get(sample.sample_id, []),
                                      args.recapture, args.retry_failed)
        for url, reason in skipped:
            print(f"SKIP     {sample.sample_id}  {url}  ({reason})")
            verdicts["skip"] += 1
        for url in todo:
            verdict = service.policy.check(unwrap_link(url))
            state = "OPEN" if verdict.allowed else f"BLOCK {verdict.code.value}"
            verdicts["open" if verdict.allowed else "block"] += 1
            print(f"{state:<8} {sample.sample_id}  {url}" + ("" if verdict.allowed else f"  ({verdict.message})"))
    print(f"\nDry run: {verdicts['open']} would be opened, {verdicts['block']} blocked, "
          f"{verdicts['skip']} skipped. Nothing was opened or written.")


def _print_capture(capture: WebpageCapture) -> None:
    if capture.status in (CaptureStatus.CAPTURED, CaptureStatus.HTTP_ERROR):
        label = "CAPTURED" if capture.status is CaptureStatus.CAPTURED else f"HTTP {capture.http_status}"
        title = f'  "{capture.page_title}"' if capture.page_title else ""
        print(f"{label:<9} {capture.sample_id}  {capture.original_url}\n"
              f"          -> {capture.final_url} [{capture.final_domain}]  {capture.screenshot}{title}")
    else:
        print(f"{capture.status.value.upper():<9} {capture.sample_id}  {capture.original_url}  "
              f"[{capture.error_code.value}] {capture.error_message}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture destination web pages of dataset samples.")
    target = parser.add_argument_group("selection")
    target.add_argument("--sample-id", action="append", help="Sample to capture (repeatable)")
    target.add_argument("--all", action="store_true", help="Every sample that has a URL")
    target.add_argument("--source-dataset", help="Only samples whose source_dataset contains this text")
    target.add_argument("--platform", choices=[p.value for p in Platform])
    target.add_argument("--is-scam", type=int, choices=[0, 1], help="0 = legitimate only, 1 = scam only")
    target.add_argument("--limit", type=int, help="At most this many samples")
    target.add_argument("--include-synthetic", action="store_true", help="Also select synthetic_test samples")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be opened; open nothing")
    parser.add_argument("--retry-failed", action="store_true", help="Retry URLs whose earlier attempt failed")
    parser.add_argument("--recapture", action="store_true", help="Capture again URLs already captured")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between URLs (default 1)")
    parser.add_argument("--allow-scam-urls", action="store_true",
                        help="Required to open samples labelled as scams (use a VM / Windows Sandbox)")
    parser.add_argument("--data-dir", help="Alternative data directory")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    setup(args.verbose)

    if not (args.sample_id or args.all or args.source_dataset or args.platform or args.is_scam is not None):
        parser.error("choose samples with --sample-id, --all, --source-dataset, --platform or --is-scam")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.delay < 0:
        parser.error("--delay cannot be negative")

    settings = load_settings(args.data_dir)
    service = WebCaptureService(settings)
    try:
        samples = _select(service, args)
    except ServiceError as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    if not samples:
        print("No selected sample has a URL to capture.")
        return 0

    scam_samples = [s.sample_id for s in samples if s.labels.is_scam is IsScam.SCAM]
    print(f"Selected {len(samples)} sample(s) with URLs"
          + (f", {len(scam_samples)} labelled as scam" if scam_samples else "") + ".")
    if args.dry_run:
        _dry_run(service, samples, args)
        return 0
    if scam_samples and not args.allow_scam_urls:
        print("ERROR: the selection contains samples labelled as scams. Opening scam URLs must be done from a "
              "disposable VM or Windows Sandbox; rerun there with --allow-scam-urls, or select --is-scam 0.",
              file=sys.stderr)
        return 2

    try:
        outcomes = service.capture_samples(
            [s.sample_id for s in samples], recapture=args.recapture, retry_failed=args.retry_failed,
            delay_seconds=args.delay, on_capture=_print_capture,
        )
    except ServiceError as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1

    statuses = Counter(c.status.value for o in outcomes for c in o.captures)
    skipped = sum(len(o.skipped) for o in outcomes)
    if args.verbose:
        for outcome in outcomes:
            for url, reason in outcome.skipped:
                print(f"SKIP      {outcome.sample_id}  {url}  ({reason})")
    print(f"\nCaptured {statuses['captured']}, HTTP error {statuses['http_error']}, failed {statuses['failed']}, "
          f"blocked/skipped {statuses['skipped']}; not attempted {skipped} (already done; use -v to list).")
    print(f"Records: {settings.webpage_captures_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
