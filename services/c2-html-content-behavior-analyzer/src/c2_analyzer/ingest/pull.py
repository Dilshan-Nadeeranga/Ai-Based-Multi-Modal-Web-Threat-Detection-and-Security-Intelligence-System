"""Daily backup PULL of ThreatRadar's data files into the analysis queue.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why (viva): the push (ThreatRadar -> POST /api/v1/ingest) is the fast path, but a push
can be lost (C2 restarting, network error, ThreatRadar's retry gave up). Once a day this
pull reads ThreatRadar's own output files - with the SAME parsers as the Part 1 dataset
import (``feeds.read_threatradar_rows``) - and queues every URL C2 has NEVER seen as
``threatradar_pull``. URLs already queued / analysed at any time are skipped (otherwise
each run would re-analyse the whole history), allow-listed sites are skipped like in a
push. Unlike the dataset import, no keyword rule is needed: the analysis decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from c2_analyzer.api.guards import normalize_url
from c2_analyzer.dataset.feeds import (
    THREATRADAR_SOURCES,
    ThreatRadarImport,
    load_threatradar_rules,
    read_threatradar_rows,
)
from c2_analyzer.ingest.service import EnqueueResult, IngestService, UrlItem


@dataclass
class PullReport:
    read: dict[str, int] = field(default_factory=dict)
    before_since: int = 0
    over_limit: int = 0
    missing_files: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    queued: EnqueueResult = field(default_factory=EnqueueResult)


def pull_threatradar(
    data_dir: Path,
    service: IngestService,
    since: date | None = None,
    sources: tuple[str, ...] = THREATRADAR_SOURCES,
    limit: int | None = None,
) -> PullReport:
    """Queue the new URLs found in ``data_dir`` (ingestion/threat-radar/backend/data)."""
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        raise FileNotFoundError(f"ThreatRadar data folder not found: {data_dir}")
    rules = load_threatradar_rules()
    scan = ThreatRadarImport()
    report = PullReport()
    items: list[UrlItem] = []
    for row, file_name, _ in read_threatradar_rows(data_dir, sources, rules, scan):
        if since is not None and (row.day is None or row.day < since):
            report.before_since += 1
            continue
        ref = {**row.ref, "file": file_name}
        if row.day:
            ref["seen"] = row.day.isoformat()
        items.append(UrlItem(url=row.url, source_ref=ref))
    # --limit caps NEW URLs: known ones are dropped first, so a limited daily run still
    # moves forward instead of re-reading the same first rows.
    # Invalid / allow-listed rows never get a job, so they must not use up the limit either
    # (they are still passed on, to be counted as rejected).
    bad = [item for item in items if service.url_problem(item.url)]
    good = [item for item in items if not service.url_problem(item.url)]
    known = service.store.known_urls([normalize_url(i.url) or "" for i in good])
    fresh = [item for item in good if normalize_url(item.url) not in known]
    already_known = len(good) - len(fresh)
    if limit is not None and len(fresh) > limit:
        report.over_limit = len(fresh) - limit
        fresh = fresh[:limit]
    report.read = dict(scan.read)
    report.missing_files = list(scan.missing_files)
    report.unreadable = list(scan.rejected)
    report.queued = service.enqueue(bad + fresh, "threatradar_pull", skip_known=True)
    report.queued.already_known += already_known
    return report
