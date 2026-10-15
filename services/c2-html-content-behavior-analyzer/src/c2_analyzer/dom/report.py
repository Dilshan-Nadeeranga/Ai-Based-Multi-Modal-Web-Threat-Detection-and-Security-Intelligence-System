"""Descriptive report of the DOM features of one dataset version.

Part 3: DOM structural analysis.

Why: before Part 4 trains anything I need to see whether the features make
sense - and the thesis needs the tables:

    reports/dom_features/<version>_summary.json / .md
    reports/dom_features/figures/<version>_top_features_boxplots.png
    reports/dom_features/figures/<version>_feature_correlation.png

Contents: run counts and timing; per label the mean / median / % non-zero of
every feature; WARNINGS for constant / near-constant features (no information)
and highly correlated pairs (|r| > 0.95, redundant); and the features that
SEPARATE the labels most, ranked by mutual information with the label, with
a robust "median spread" next to it (largest minus smallest per-label median,
divided by the overall IQR). This ranking is descriptive only - NOT a model and
not a feature selection (Part 4 decides, on the training split only).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from matplotlib.figure import Figure

from c2_analyzer.config import get_labels
from c2_analyzer.dataset.page_view import terminal_safe
from c2_analyzer.dataset.statistics import quantile
from c2_analyzer.dataset.stats_report import DPI, label_color, md_table
from c2_analyzer.dom.dictionary import dictionary_hash, load_dictionary, specs
from c2_analyzer.dom.exporter import feature_frame, reports_dir
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.utils.io import atomic_write_text, write_json

RANDOM_STATE = 42


def _num(value: float) -> float:
    return round(float(value), 4)


def constant_features(frame: pd.DataFrame, near_share: float) -> tuple[list[str], dict[str, float]]:
    """(constant features, near-constant feature -> share of its most common value)."""
    constant, near = [], {}
    for name in specs():
        column = frame[name]
        if column.nunique(dropna=False) <= 1:
            constant.append(name)
            continue
        share = float(column.value_counts(normalize=True).iloc[0])
        if share >= near_share:
            near[name] = round(share, 3)
    return constant, near


def correlated_pairs(frame: pd.DataFrame, skip: set[str], threshold: float) -> list[dict]:
    """Feature pairs with |Pearson r| > threshold (constant columns skipped)."""
    names = [name for name in specs() if name not in skip]
    if len(frame) < 3 or len(names) < 2:
        return []
    corr = frame[names].astype(float).corr()
    pairs = []
    for i, first in enumerate(names):
        for second in names[i + 1 :]:
            r = corr.loc[first, second]
            if pd.notna(r) and abs(r) > threshold:
                pairs.append({"a": first, "b": second, "r": _num(r)})
    return sorted(pairs, key=lambda pair: -abs(pair["r"]))


def separation(frame: pd.DataFrame, labels: list[str], skip: set[str]) -> list[dict]:
    """Per feature: mutual information with the label + median spread / IQR. Descriptive."""
    names = [name for name in specs() if name not in skip]
    if len(labels) < 2 or not names:
        return []
    from sklearn.feature_selection import mutual_info_classif  # heavy import, only here

    data = frame[frame["label"].isin(labels)]
    discrete = [specs()[name].type == "binary" for name in names]
    mi = mutual_info_classif(
        data[names].astype(float).to_numpy(),
        data["label"].to_numpy(),
        discrete_features=np.array(discrete),
        random_state=RANDOM_STATE,
    )
    result = []
    for name, score in zip(names, mi, strict=True):
        column = data[name].astype(float)
        medians = data.groupby("label")[name].median()
        iqr = float(column.quantile(0.75) - column.quantile(0.25)) or float(column.std() or 0)
        spread = float(medians.max() - medians.min())
        result.append(
            {
                "feature": name,
                "mutual_information": _num(score),
                "median_spread": _num(spread / iqr) if iqr else 0.0,
                "medians": {label: _num(medians[label]) for label in labels},
            }
        )
    return sorted(result, key=lambda row: (-row["mutual_information"], -row["median_spread"]))


def summarize(
    rows: list[dict], results: list[dict], version: str, wall_seconds: float, filters: dict
) -> dict:
    """Everything in <version>_summary.json."""
    dictionary = load_dictionary()
    settings = dictionary.report
    frame = feature_frame(rows)
    labels = [label for label in get_labels() if (frame["label"] == label).any()]

    per_label = {}
    for label in labels:
        part = frame[frame["label"] == label]
        per_label[label] = {
            "pages": len(part),
            "mean": {name: _num(part[name].mean()) for name in specs()},
            "median": {name: _num(part[name].median()) for name in specs()},
            "pct_nonzero": {name: _num(100 * (part[name] != 0).mean()) for name in specs()},
        }

    constant, near = constant_features(frame, float(settings.get("near_constant_share", 0.95)))
    pairs = correlated_pairs(
        frame, set(constant), float(settings.get("correlation_threshold", 0.95))
    )
    ranking = separation(frame, labels, set(constant))

    done = [r for r in results if r["status"] != "failed"]
    times = [r["processing_ms"] for r in done if r["status"] == "processed"]
    return {
        "version": version,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "feature_set_version": dictionary.feature_set_version,
        "dictionary_hash": dictionary_hash(),
        "feature_count": len(specs()),
        "filters": filters,
        "counts": {
            "rows_in_csv": len(frame),
            "run_total": len(results),
            "processed": sum(r["status"] == "processed" for r in results),
            "skipped_unchanged": sum(r["status"] == "skipped" for r in results),
            "failed": sum(r["status"] == "failed" for r in results),
            "part2_processed_now": sum(r.get("part2") == "processed" for r in results),
            "pages_with_group_errors": sum(bool(r.get("errors")) for r in done),
        },
        "failures": [
            {"sample_id": r["sample_id"], "error": r["error"]}
            for r in results
            if r["status"] == "failed"
        ],
        "group_errors": [
            {"sample_id": r["sample_id"], "errors": r["errors"]} for r in done if r.get("errors")
        ],
        "timing": {
            "wall_seconds": round(wall_seconds, 1),
            "pages_timed": len(times),
            "avg_ms": round(sum(times) / len(times), 1) if times else None,
            "p95_ms": quantile(times, 0.95),
            "max_ms": max(times) if times else None,
        },
        "labels": labels,
        "per_label": per_label,
        "warnings": {
            "constant_features": constant,
            "near_constant_features": near,
            "correlated_pairs": pairs,
        },
        "separation": ranking,
        "top_separating": [
            row["feature"] for row in ranking[: int(settings.get("top_separating", 12))]
        ],
    }


def warning_lines(warn: dict) -> list[str]:
    """The three warning lists as readable lines (Markdown report and CLI)."""
    near = warn["near_constant_features"]
    pairs = warn["correlated_pairs"]
    constant_text = ", ".join(warn["constant_features"]) or "none"
    near_text = ", ".join(f"{name} ({share:.0%})" for name, share in near.items()) or "none"
    pairs_text = ", ".join(f"{p['a']} ~ {p['b']} (r={p['r']})" for p in pairs) or "none"
    return [
        f"Constant features ({len(warn['constant_features'])}): {constant_text}",
        f"Near-constant features ({len(near)}): {near_text}",
        f"Highly correlated pairs ({len(pairs)}): {pairs_text}",
    ]


# ---- Markdown ---------------------------------------------------------------------------------


def _cell(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:,.3g}" if abs(value) < 1000 else f"{value:,.0f}"
    return str(value)


def render_markdown(summary: dict, figures: list[Path]) -> str:
    counts, timing, warn = summary["counts"], summary["timing"], summary["warnings"]
    labels = summary["labels"]
    out = [
        f"# DOM features summary - dataset {summary['version']}",
        "",
        f"- Generated: {summary['generated_at']}",
        f"- Feature set: {summary['feature_set_version']} ({summary['feature_count']} features, "
        f"dictionary {summary['dictionary_hash'][:12]})",
        f"- Rows in dom_features.csv: {counts['rows_in_csv']}",
        f"- This run: {counts['run_total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']}; "
        f"Part 2 run for {counts['part2_processed_now']} missing page(s); "
        f"pages with a failed feature group: {counts['pages_with_group_errors']}",
        f"- Time per page: avg {timing['avg_ms']} ms, p95 {timing['p95_ms']} ms, "
        f"max {timing['max_ms']} ms (wall time {timing['wall_seconds']} s)",
        "",
        "> Descriptive statistics only - no model. Separation = mutual information with the "
        "label; spread = (largest - smallest label median) / overall IQR.",
        "",
        "## Most separating features",
        "",
    ]
    top = summary["separation"][: len(summary["top_separating"])]
    nonzero = {label: summary["per_label"][label]["pct_nonzero"] for label in labels}
    out.append(
        md_table(
            ["feature", "MI", "spread"]
            + [f"median {label}" for label in labels]
            + [f"% non-zero {label}" for label in labels],
            [
                [
                    row["feature"],
                    _cell(row["mutual_information"]),
                    _cell(row["median_spread"]),
                    *[_cell(row["medians"][label]) for label in labels],
                    *[_cell(nonzero[label][row["feature"]]) for label in labels],
                ]
                for row in top
            ],
        )
    )
    out += ["", "## Warnings", ""]
    out += [f"- {line}" for line in warning_lines(warn)]
    if summary["failures"]:
        out += ["", "## Failures", ""]
        out += [f"- {f['sample_id']}: {f['error']}" for f in summary["failures"]]

    out += ["", "## All features per label (median / mean / % non-zero)", ""]
    out.append(
        md_table(
            ["feature", "group", *labels],
            [
                [
                    name,
                    spec.group,
                    *[
                        f"{_cell(summary['per_label'][l]['median'][name])} / "
                        f"{_cell(summary['per_label'][l]['mean'][name])} / "
                        f"{_cell(summary['per_label'][l]['pct_nonzero'][name])}%"
                        for l in labels  # noqa: E741
                    ],
                ]
                for name, spec in specs().items()
            ],
        )
    )
    if figures:
        out += ["", "## Figures", ""]
        out += [f"![{path.stem}](figures/{path.name})" for path in figures]
    return "\n".join(out) + "\n"


# ---- figures ------------------------------------------------------------------------------------


def figure_boxplots(
    frame: pd.DataFrame, features: list[str], labels: list[str], path: Path
) -> Path:
    """One box plot per top feature, a box per label (outliers shown as dots)."""
    columns = 4
    rows = max(1, -(-len(features) // columns))
    fig = Figure(figsize=(4 * columns, 3.2 * rows))
    for index, name in enumerate(features):
        ax = fig.add_subplot(rows, columns, index + 1)
        data = [frame.loc[frame["label"] == label, name].astype(float) for label in labels]
        boxes = ax.boxplot(data, patch_artist=True, showfliers=True, flierprops={"markersize": 2})
        ax.set_xticks(range(1, len(labels) + 1), labels, rotation=20, fontsize=7)
        for patch, label in zip(boxes["boxes"], labels, strict=True):
            patch.set_facecolor(label_color(label))
            patch.set_alpha(0.6)
        if frame[name].astype(float).max() > 100:
            ax.set_yscale("symlog", linthresh=1)  # log-like for big counts, but 0 stays visible
        ax.set_ylim(bottom=0)  # every DOM feature is >= 0
        ax.set_title(name, fontsize=9)
        ax.tick_params(axis="y", labelsize=7)
    fig.suptitle("Top separating DOM features by label (descriptive)", fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=DPI)
    return path


def figure_correlation(frame: pd.DataFrame, features: list[str], path: Path) -> Path:
    """Pearson correlation heatmap of the non-constant features."""
    size = max(8.0, 0.22 * len(features) + 3)
    fig = Figure(figsize=(size, size * 0.9))
    ax = fig.add_subplot(1, 1, 1)
    corr = frame[features].astype(float).corr().fillna(0).to_numpy()
    image = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(features)), features, rotation=90, fontsize=6)
    ax.set_yticks(range(len(features)), features, fontsize=6)
    fig.colorbar(image, ax=ax, shrink=0.7, label="Pearson r")
    ax.set_title("DOM feature correlation")
    fig.tight_layout()
    fig.savefig(path, dpi=DPI)
    return path


def write_report(summary: dict, rows: list[dict], out_dir: Path | None = None) -> list[Path]:
    """Write JSON + Markdown + figures. Returns all written paths."""
    directory = out_dir or reports_dir()
    figures_dir = directory / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)
    frame = feature_frame(rows)
    version = summary["version"]
    figures = []
    if summary["top_separating"] and len(summary["labels"]) >= 2:
        figures.append(
            figure_boxplots(
                frame,
                summary["top_separating"],
                summary["labels"],
                figures_dir / f"{version}_top_features_boxplots.png",
            )
        )
    constant = set(summary["warnings"]["constant_features"])
    usable = [name for name in specs() if name not in constant]
    if len(frame) >= 3 and len(usable) >= 2:
        figures.append(
            figure_correlation(frame, usable, figures_dir / f"{version}_feature_correlation.png")
        )
    json_path = directory / f"{version}_summary.json"
    md_path = directory / f"{version}_summary.md"
    write_json(summary, json_path)
    atomic_write_text(render_markdown(summary, figures), md_path)
    return [json_path, md_path, *figures]


def label_medians(version: str, out_dir: Path | None = None) -> dict[str, dict[str, float]]:
    """{label: {feature: median}} from a written summary (inspector comparison), or {}."""
    path = (out_dir or reports_dir()) / f"{version}_summary.json"
    if not path.is_file():
        return {}
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    if summary.get("dictionary_hash") != dictionary_hash():
        return {}  # made with another dictionary - do not compare apples with pears
    return {label: data["median"] for label, data in summary.get("per_label", {}).items()}


# ---- text views for the CLI ---------------------------------------------------------------------


def describe_result(result: DomResult, label: str | None = None) -> str:
    """One page's features grouped by group, then its evidence (CLI ``one``)."""
    dictionary = load_dictionary()
    lines = [
        f"{result.sample_id or '(ad-hoc page)'}"
        + (f"  ({label})" if label else "")
        + (f"  dataset {result.dataset_version}" if result.dataset_version else ""),
        f"Feature set {result.feature_set_version}: {len(result.features)} features, "
        f"tree from {result.tree_source}, {result.processing_ms} ms",
    ]
    for message in result.errors:
        lines.append(f"ERROR   {message}")
    for message in result.warnings:
        lines.append(f"WARNING {message}")
    for group in dictionary.groups:
        names = [spec.name for spec in dictionary.features if spec.group == group]
        lines.append("")
        lines.append(f"[{group}]")
        for name in names:
            value = result.features[name]
            mark = "" if value else "  ."
            shown = f"{value:g}" if isinstance(value, float) else str(value)
            lines.append(f"  {name:<36}{shown:>12}{mark}")
    lines.append("")
    lines.append(f"Evidence ({len(result.evidence)}):")
    for item in result.evidence:
        lines.append(f"  [{item.severity.upper():<6}] {terminal_safe(item.message)}")
    return "\n".join(lines)


def describe_dictionary() -> str:
    """The feature dictionary as a text table (CLI ``describe``, for the report)."""
    dictionary = load_dictionary()
    lines = [
        f"DOM feature dictionary {dictionary.feature_set_version} - "
        f"{len(dictionary.features)} features (configs/dom_features.yaml)",
        "",
        f"{'#':>3}  {'feature':<36}{'group':<17}{'type':<8}description",
    ]
    for index, spec in enumerate(dictionary.features, 1):
        flag = " [needs page URL]" if spec.needs_page_url else ""
        lines.append(
            f"{index:>3}  {spec.name:<36}{spec.group:<17}{spec.type:<8}{spec.description}{flag}"
        )
    return "\n".join(lines)


def dictionary_markdown() -> str:
    """The same table in Markdown (paste into the thesis)."""
    return md_table(
        ["#", "feature", "group", "type", "description"],
        [
            [i, f"`{spec.name}`", spec.group, spec.type, spec.description]
            for i, spec in enumerate(load_dictionary().features, 1)
        ],
    )
