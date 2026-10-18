"""Numbers for the dashboard: live overview (from the results store) and the research
summary (read-only, from the reports earlier Parts already wrote).

Part 9: Batch B-2 - read APIs for the team frontend.

- ``overview``: counts in a time window (24h / 7d / 30d): by verdict, status, threat
  class, source, language; the most targeted (registrable) domains and imitated brands of
  FLAGGED scans; a time series; queue depth, review queue and worker state. Aggregated in
  Python over the window's rows - a few thousand rows a day is far below where SQL
  tuning would matter, and the code stays readable.
- Imitated brand: ThreatRadar's own ``brand_mimicry:<brand>`` reason if present, else
  a brand of configs/threatradar_rules.yaml found inside the host (``paypal-verify.xyz``
  -> paypal), allow-listed (real) brand sites excluded.
- ``research_summary``: NEVER retrains or regenerates anything; it only reads JSON
  reports (dataset manifest, ablation table with bootstrap CIs, verdict operating
  points, model card). A missing report is listed in ``missing``, not an error.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from c2_analyzer.config import project_root
from c2_analyzer.dataset.feeds import is_allow_listed, load_threatradar_rules
from c2_analyzer.schemas.ingest import (
    CountItem,
    SeriesPoint,
    StatsOverview,
    WorkerStatus,
)
from c2_analyzer.store.repository import ResultsStore, iso, parse_iso
from c2_analyzer.utils.defang import defang_host
from c2_analyzer.utils.url import domain_of_host

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
FLAGGED = ("Suspicious", "Malicious")


def _brand(row: dict, brands: tuple[str, ...], allow_list: tuple[str, ...]) -> str | None:
    ref = json.loads(row.get("source_ref") or "{}")
    for reason in ref.get("reasons") or []:
        if str(reason).startswith("brand_mimicry:"):
            return str(reason).split(":", 1)[1].strip().lower() or None
    host = (row.get("final_url_domain") or "").lower()
    if not host or is_allow_listed(f"https://{host}/", allow_list):
        return None
    return next((brand for brand in brands if brand in host), None)


def _bucket_start(moment: datetime, bucket: str) -> datetime:
    moment = moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    return moment.replace(hour=0) if bucket == "day" else moment


def overview(
    store: ResultsStore, window: str, worker: WorkerStatus, top_n: int = 10
) -> StatsOverview:
    """The ``/api/v1/stats/overview`` numbers for one window."""
    if window not in WINDOWS:
        raise ValueError(f"window must be one of {', '.join(WINDOWS)}")
    now = store.clock()
    start = now - WINDOWS[window]
    since = iso(start)
    rows = store.window_rows(since)
    rules = load_threatradar_rules()

    by_verdict: Counter = Counter({"Legitimate": 0, "Suspicious": 0, "Malicious": 0})
    by_status, by_class, by_source, by_language = Counter(), Counter(), Counter(), Counter()
    domains, brands = Counter(), Counter()
    bucket = "day" if window == "30d" else "hour"
    step = timedelta(days=1) if bucket == "day" else timedelta(hours=1)
    series: dict[datetime, list[int]] = {}
    moment = _bucket_start(start, bucket)
    while moment <= now:
        series[moment] = [0, 0]
        moment += step

    for row in rows:
        verdict = row["verdict"]
        by_verdict[verdict or "none"] += 1
        by_status[row["status"]] += 1
        by_source[row["source"]] += 1
        by_language[row["page_language"] or "unknown"] += 1
        if row["threat_class"]:
            by_class[row["threat_class"]] += 1
        flagged = verdict in FLAGGED
        if flagged and row["final_url_domain"]:
            domains[domain_of_host(row["final_url_domain"])] += 1
            brand = _brand(row, rules.brands, rules.allow_list)
            if brand:
                brands[brand] += 1
        point = series.get(_bucket_start(parse_iso(row["created_at"]), bucket))
        if point is not None:
            point[0] += 1
            point[1] += int(flagged)

    return StatsOverview(
        window=window,
        since=since,
        generated_at=iso(now),
        total=len(rows),
        duplicates_skipped=store.duplicates_since(since),
        by_verdict=dict(by_verdict),
        by_status=dict(by_status),
        by_threat_class=dict(by_class.most_common()),
        by_source=dict(by_source.most_common()),
        by_language=dict(by_language.most_common()),
        top_domains=[
            CountItem(key=defang_host(key) or key, count=count)
            for key, count in domains.most_common(top_n)
        ],
        top_brands=[CountItem(key=key, count=count) for key, count in brands.most_common(top_n)],
        series_bucket=bucket,
        series=[
            SeriesPoint(t=iso(moment), total=total, flagged=flagged)
            for moment, (total, flagged) in series.items()
        ],
        queue=store.job_counts(),
        review=store.review_counts(),
        worker=worker,
    )


# ---- research page (read-only) ---------------------------------------------------------


def _read_json(path: Path, missing: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        missing.append(str(path.relative_to(project_root())).replace("\\", "/"))
        return None


def _ablation_row(entry: dict) -> dict:
    test, cv, boot = entry.get("test") or {}, entry.get("cv") or {}, entry.get("bootstrap") or {}
    point = entry.get("operating_point") or {}
    constrained = (point.get("test") or {}).get("fpr_constrained") or {}
    return {
        "key": entry.get("key"),
        "row": entry.get("row"),
        "title": entry.get("title"),
        "group": entry.get("group"),
        "arms": entry.get("arms"),
        "strategy": entry.get("strategy_display") or entry.get("strategy"),
        "selected_for_row": entry.get("selected_for_row"),
        "cv_macro_f1_mean": (cv.get("mean") or {}).get("macro_f1"),
        "cv_macro_f1_std": (cv.get("std") or {}).get("macro_f1"),
        "test_macro_f1": test.get("macro_f1"),
        "test_macro_f1_ci": [boot.get("ci_low"), boot.get("ci_high")],
        "test_accuracy": test.get("accuracy"),
        "test_roc_auc": test.get("roc_auc_ovr_macro"),
        "test_benign_fpr": test.get("benign_fpr"),
        # the same row at the <= 2 % OOF benign-FPR operating point (Part 9A)
        "threshold": point.get("threshold"),
        "benign_fpr_at_threshold": constrained.get("benign_fpr"),
        "macro_f1_at_threshold": constrained.get("macro_f1"),
        "threat_recall_at_threshold": constrained.get("threat_recall"),
    }


def _label_by_language(path: Path) -> dict[str, dict[str, int]]:
    """class x language counts from the frozen manifest CSV (ids, labels, languages only)."""
    table: dict[str, Counter] = {}
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                table.setdefault(row["label"], Counter())[row.get("language") or "unknown"] += 1
    except (OSError, KeyError, csv.Error):
        return {}
    return {label: dict(counts) for label, counts in table.items()}


def research_summary(version: str) -> dict:
    """Numbers for the research page, read from existing reports (nothing regenerated)."""
    root = project_root()
    missing: list[str] = []
    manifest = _read_json(root / "data/metadata/manifests" / f"dataset_{version}.json", missing)
    ablation = _read_json(root / "reports/ablation" / version / "ablation.json", missing)
    operating = _read_json(root / "reports/verdict" / f"{version}_operating_points.json", missing)
    card = _read_json(root / "models/fusion" / version / "model_card.json", missing)

    dataset = None
    if manifest:
        dataset = {
            "version": manifest.get("version"),
            "created_at": manifest.get("created_at"),
            "total": manifest.get("total"),
            "counts_per_label": manifest.get("counts_per_label"),
            "counts_per_language": manifest.get("counts_per_language"),
            "fingerprint": manifest.get("fingerprint"),
            "label_by_language": _label_by_language(
                root / "data/metadata/manifests" / f"dataset_{version}.csv"
            ),
        }
    ablation_part = None
    if ablation:
        ablation_part = {
            "classes": ablation.get("classes"),
            "arms_available": ablation.get("arms_available"),
            "benign_fpr_target": ablation.get("benign_fpr_target"),
            "bootstrap": ablation.get("bootstrap_settings"),
            "rows": [_ablation_row(entry) for entry in ablation.get("entries") or []],
            "final": _ablation_row(ablation["final"]) if ablation.get("final") else None,
            "comparison": ablation.get("comparison"),
        }
    points = None
    if operating:
        points = {
            "calibration": operating.get("calibration"),
            "oof": operating.get("oof"),  # per arm subset + floor rules fired (counts only)
            "test": [
                {k: v for k, v in run.items() if k not in ("pages", "parity")}
                for run in operating.get("test") or []
            ],
        }
    models = None
    if card:
        models = {
            "fusion": {
                "name": card.get("name"),
                "created_at": card.get("created_at"),
                "strategy": card.get("strategy_display") or card.get("strategy"),
                "weights": (card.get("params") or {}).get("weights"),
                "cv_mean": card.get("cv_mean"),
                "test": card.get("test"),
            },
            "arms": {
                arm: {
                    key: info.get(key)
                    for key in ("part", "model_display", "model_trained_at", "seed", "base_model")
                    if info.get(key) is not None
                }
                for arm, info in (card.get("arm_models") or {}).items()
            },
        }
    return {
        "version": version,
        "dataset": dataset,
        "ablation": ablation_part,
        "operating_points": points,
        "models": models,
        "missing": missing,
    }
