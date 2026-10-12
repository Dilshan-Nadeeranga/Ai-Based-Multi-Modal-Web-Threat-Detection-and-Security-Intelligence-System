"""Write the dataset statistics as JSON, Markdown tables and PNG figures.

Part 1: Multilingual dataset preparation (Batch D, Task 13).

Why: statistics.py computes the numbers; this module only presents them.
The Markdown file is meant to be pasted into the progress report, the JSON
is for scripts, and the figures are for slides and the thesis.

Figures use matplotlib's object API (``matplotlib.figure.Figure``) and are
saved as PNG through the Agg renderer: no window is ever opened, so it works
in tests, over SSH and in Docker.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from matplotlib.figure import Figure

from c2_analyzer.config import get_labels, get_languages
from c2_analyzer.dataset.quality import usable_flags
from c2_analyzer.dataset.statistics import PageFacts
from c2_analyzer.dataset.views import VIEWS, select_view

DPI = 150
FIGURE_NAMES = (
    "label_distribution.png",
    "label_language_heatmap.png",
    "quality_flags.png",
    "text_length_by_label.png",
    "collection_timeline.png",
    "verification_progress.png",
)
# One fixed colour per label (matplotlib "tab10"), the same in every figure.
LABEL_COLORS = ["#2ca02c", "#d62728", "#ff7f0e", "#9467bd", "#8c564b"]
VIEW_COLORS = {"all": "#c7c7c7", "usable": "#7fa7d4", "clean": "#1f4e79"}


def label_color(label: str) -> str:
    return LABEL_COLORS[get_labels().index(label) % len(LABEL_COLORS)]


# ---- JSON + Markdown ---------------------------------------------------------------------------


def write_json(stats: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    """A GitHub-flavoured Markdown table."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += [
        "| " + " | ".join("" if cell is None else str(cell) for cell in row) + " |" for row in rows
    ]
    return "\n".join(lines)


def size_text(size: float | None) -> str:
    return "-" if size is None else f"{size / 1024:.1f} KB"


def number_text(value: float | None) -> str:
    return "-" if value is None else f"{value:,.0f}"


def pick_view(stats: dict[str, Any], preferred: str) -> tuple[str, dict[str, Any]]:
    """The preferred view's statistics, or the first one computed (stats --view X)."""
    views = stats["views"]
    name = preferred if preferred in views else next(iter(views))
    return name, views[name]


def render_markdown(stats: dict[str, Any], figures: list[Path]) -> str:
    """The human-readable report (paste-ready tables)."""
    labels, languages = get_labels(), get_languages()
    views = stats["views"]
    out = ["# C2 dataset statistics", ""]
    out.append(f"- Generated: {stats['generated_at']}")
    latest = stats["latest_frozen_version"] or "none"
    out.append(f"- Dataset version: **{stats['dataset_version']}** (latest frozen: {latest})")
    for view, definition in stats["definitions"].items():
        out.append(f"- **{view}** view: {definition}")

    out += ["", "## Samples per label and view", ""]
    rows = [
        [view, views[view]["total"]] + [views[view]["per_label"][label] for label in labels]
        for view in views
    ]
    out.append(md_table(["view", "total", *labels], rows))

    out += ["", "## Readiness (clean view vs configs/collection_targets.yaml)", ""]
    ready = stats["readiness"]
    local = list(next(iter(ready["labels"].values()))["languages"]) if ready["labels"] else []
    rows = []
    for label, item in ready["labels"].items():
        per_language = [
            f"{item['languages'][lang]['have']}/{item['languages'][lang]['target']}"
            for lang in local
        ]
        rows.append([label, f"{item['have']}/{item['target']}", *per_language, item["status"]])
    out.append(
        md_table(
            ["label", "clean / target", *(f"{lang} / target" for lang in local), "status"], rows
        )
    )
    coverage = ", ".join(
        f"{c['name']} {c['samples']} ({c['percent_of_clean']}%)"
        for c in ready["language_coverage"].values()
    )
    out.append("")
    out.append(
        f"Local-language coverage (clean): {coverage}; mixed-language pages: "
        f"{ready['mixed_language_samples']}."
    )

    name, view = pick_view(stats, "clean")
    out += ["", f"## Label x language ({name} view)", ""]
    rows = [
        [
            label,
            *(view["label_by_language"][label][lang] for lang in languages),
            view["per_label"][label],
        ]
        for label in labels
    ]
    rows.append(["**total**", *(view["per_language"][lang] for lang in languages), view["total"]])
    out.append(md_table(["label", *languages, "total"], rows))

    balance = view["imbalance"]
    out += ["", f"## Class balance ({name} view)", ""]
    out.append(
        md_table(
            ["label", "samples", "% of total"],
            [
                [label, view["per_label"][label], balance["percent"].get(label, 0)]
                for label in labels
            ],
        )
    )
    ratio = "undefined (a class has no samples)" if balance["ratio"] is None else balance["ratio"]
    out.append("")
    out.append(
        f"Majority/minority ratio: **{ratio}** "
        f"(majority {balance['majority']}, minority {balance['minority']})."
    )

    out += ["", f"## Verification ({name} view)", ""]
    out.append(
        md_table(
            ["label", "verified", "unverified", "% verified"],
            [
                [label, v["verified"], v["unverified"], v["percent_verified"]]
                for label, v in view["verification"].items()
            ],
        )
    )

    out += ["", f"## Page statistics ({name} view)", ""]
    rows = [
        [
            label,
            p["pages"],
            size_text(p["file_size_median"]),
            size_text(p["file_size_p90"]),
            number_text(p["text_chars_median"]),
            number_text(p["text_chars_p90"]),
            "-" if p["forms_mean"] is None else p["forms_mean"],
            p["percent_with_password"],
            p["percent_with_script"],
        ]
        for label, p in view["page_stats"].items()
    ]
    out.append(
        md_table(
            [
                "label",
                "pages",
                "size median",
                "size p90",
                "text chars median",
                "text chars p90",
                "forms (mean)",
                "% password field",
                "% script",
            ],
            rows,
        )
    )

    name, view = pick_view(stats, "all")
    out += ["", f"## Quality flags and exclusions ({name} view)", ""]
    out.append(
        md_table(
            ["quality_flag", "samples", "usable?"],
            [
                [flag, n, "yes" if flag in usable_flags() else "no"]
                for flag, n in view["quality_flags"].items()
                if n
            ],
        )
    )
    out.append("")
    if view["excluded_by_reason"]:
        out.append(
            md_table(
                ["exclusion_reason", "samples"],
                [[r, n] for r, n in view["excluded_by_reason"].items()],
            )
        )
    else:
        out.append("No samples excluded yet.")

    out += ["", "## Sources and fetch modes", ""]
    sources = [
        s for s in views[name]["per_source"] if any(v["per_source"][s] for v in views.values())
    ]
    out.append(
        md_table(
            ["source", *views],
            [[s, *(v["per_source"][s] for v in views.values())] for s in sources],
        )
    )
    out.append("")
    out.append(
        md_table(
            ["fetch_mode", *views],
            [
                [m, *(v["per_fetch_mode"][m] for v in views.values())]
                for m in views[name]["per_fetch_mode"]
            ],
        )
    )

    out += ["", "## Near-duplicate clusters", ""]
    out.append(
        md_table(
            ["view", "clusters", "with 2+ pages", "rows without cluster"],
            [
                [
                    v,
                    s["clusters"]["clusters"],
                    s["clusters"]["multi_page_clusters"],
                    s["clusters"]["rows_without_cluster"],
                ]
                for v, s in views.items()
            ],
        )
    )
    clusters = view["clusters"]
    out += [
        "",
        f"Duplicates per label ({name} view): "
        + ", ".join(f"{k} {n}" for k, n in clusters["duplicates_per_label"].items()),
    ]
    out.append("")
    if clusters["largest"]:
        out.append(f"Largest clusters ({name} view):")
        out.append("")
        out.append(
            md_table(
                ["cluster_id", "label", "size"],
                [[c["cluster_id"], c["label"], c["size"]] for c in clusters["largest"]],
            )
        )
    else:
        out.append("No near-duplicate groups.")

    out += ["", f"## Relabels during review ({name} view)", ""]
    relabels = view["relabels"]
    if relabels["relabelled"]:
        out.append(
            md_table(
                ["label_original -> label", "samples"],
                [
                    [f"{a} -> {b}", n]
                    for a, row in relabels["matrix"].items()
                    for b, n in row.items()
                ],
            )
        )
    else:
        out.append("No samples relabelled yet.")

    out += ["", f"## Collection timeline ({name} view)", ""]
    out.append(
        md_table(
            ["collection_date", *labels, "total"],
            [[day, *row.values(), sum(row.values())] for day, row in view["timeline"].items()],
        )
    )

    out += ["", "## Peer agreement", ""]
    peer = stats["peer_agreement"]
    if peer is None:
        out.append("Not done yet (review_labels.py export-peer / import-peer).")
    elif "error" in peer:
        out.append(peer["error"])
    else:
        out.append(
            f"{peer['rated_samples']} samples rated by a second person: agreement "
            f"{peer['agreement_percent']}%, Cohen's kappa {peer['cohen_kappa']} "
            f"({peer['kappa_interpretation']}), {peer['disagreements']} disagreement(s)."
        )

    if figures:
        out += ["", "## Figures", ""]
        out += [f"![{path.stem}](figures/{path.name})" for path in figures]
    return "\n".join(out) + "\n"


# ---- figures -----------------------------------------------------------------------------------


def _save(fig: Figure, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, dpi=DPI)
    return path


def _empty_note(ax, text: str = "no samples yet") -> None:
    ax.text(0.5, 0.5, text, ha="center", va="center", transform=ax.transAxes, color="grey")


def figure_label_distribution(df: pd.DataFrame, path: Path) -> Path:
    """Grouped bars: samples per label in the all / usable / clean views."""
    labels = get_labels()
    fig = Figure(figsize=(9, 4.8))
    ax = fig.add_subplot()
    width = 0.8 / len(VIEWS)
    for i, view in enumerate(VIEWS):
        values = select_view(df, view)["label"].value_counts().reindex(labels, fill_value=0)
        positions = [x + (i - 1) * width for x in range(len(labels))]
        bars = ax.bar(positions, values, width, label=view, color=VIEW_COLORS[view])
        ax.bar_label(bars, fontsize=7, padding=1)
    ax.set_xticks(range(len(labels)), [label.replace("_", "\n") for label in labels])
    ax.set_ylabel("samples")
    ax.set_title("Samples per label: all vs usable vs clean")
    ax.legend(title="view")
    return _save(fig, path)


def figure_label_language_heatmap(df: pd.DataFrame, path: Path) -> Path:
    """Heatmap of the clean view: rows = labels, columns = languages, numbers in each cell."""
    labels, languages = get_labels(), get_languages()
    clean = select_view(df, "clean")
    table = pd.crosstab(clean["label"], clean["language"]) if not clean.empty else pd.DataFrame()
    table = table.reindex(index=list(labels), columns=list(languages), fill_value=0)
    fig = Figure(figsize=(7.5, 4.8))
    ax = fig.add_subplot()
    image = ax.imshow(table.to_numpy(), cmap="Blues", aspect="auto")
    fig.colorbar(image, ax=ax, label="samples")
    peak = max(int(table.to_numpy().max()), 1)
    for r, label in enumerate(labels):
        for c, language in enumerate(languages):
            value = int(table.loc[label, language])
            ax.text(
                c,
                r,
                value,
                ha="center",
                va="center",
                color="white" if value > peak / 2 else "black",
            )
    ax.set_xticks(range(len(languages)), languages)
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("language")
    ax.set_title("Clean view: label x language")
    return _save(fig, path)


def figure_quality_flags(df: pd.DataFrame, path: Path) -> Path:
    """Horizontal bars of quality flags (all view); unusable flags in red."""
    found = df["quality_flag"].value_counts()
    fig = Figure(figsize=(8, 4.5))
    ax = fig.add_subplot()
    if found.empty:
        _empty_note(ax)
    else:
        found = found.sort_values()
        colors = ["#1f77b4" if flag in usable_flags() else "#d62728" for flag in found.index]
        bars = ax.barh(found.index, found.values, color=colors)
        ax.bar_label(bars, padding=2, fontsize=8)
    ax.set_xlabel("samples (blue = usable, red = proposed for exclusion)")
    ax.set_title("Quality flags (all samples)")
    return _save(fig, path)


def figure_text_length(df: pd.DataFrame, facts: dict[str, PageFacts], path: Path) -> Path:
    """Box plot of visible-text length per label (clean view, log scale)."""
    clean = select_view(df, "clean")
    groups, names = [], []
    for label in get_labels():
        ids = clean.loc[clean["label"] == label, "sample_id"]
        lengths = [max(facts[i].text_chars, 1) for i in ids if i in facts]  # log scale needs > 0
        if lengths:
            groups.append(lengths)
            names.append(f"{label}\n(n={len(lengths)})")
    fig = Figure(figsize=(9, 4.8))
    ax = fig.add_subplot()
    if groups:
        ax.boxplot(groups)
        ax.set_xticks(range(1, len(names) + 1), names)
        ax.set_yscale("log")
    else:
        _empty_note(ax)
    ax.set_ylabel("visible text (characters, log scale)")
    ax.set_title("Visible text length per label (clean view)")
    return _save(fig, path)


def figure_timeline(df: pd.DataFrame, path: Path) -> Path:
    """Stacked bars: samples collected per day, coloured by label (all view)."""
    labels = get_labels()
    table = pd.crosstab(df["collection_date"], df["label"]) if not df.empty else pd.DataFrame()
    table = table.reindex(columns=list(labels), fill_value=0).sort_index()
    fig = Figure(figsize=(max(7, 0.6 * len(table) + 3), 4.8))
    ax = fig.add_subplot()
    if table.empty:
        _empty_note(ax)
    else:
        bottom = [0] * len(table)
        for label in labels:
            values = table[label].tolist()
            ax.bar(table.index, values, bottom=bottom, label=label, color=label_color(label))
            bottom = [b + v for b, v in zip(bottom, values, strict=True)]
        ax.tick_params(axis="x", labelrotation=45)
        ax.legend(fontsize=8)
    ax.set_ylabel("samples collected")
    ax.set_title("Collection timeline (all samples)")
    return _save(fig, path)


def figure_verification(df: pd.DataFrame, path: Path) -> Path:
    """Stacked horizontal bars: verified vs unverified per label (clean view), with %."""
    labels = list(get_labels())
    clean = select_view(df, "clean")
    verified = [
        int(((clean["label"] == lab) & (clean["verified"] == "true")).sum()) for lab in labels
    ]
    total = [int((clean["label"] == lab).sum()) for lab in labels]
    unverified = [t - v for t, v in zip(total, verified, strict=True)]
    fig = Figure(figsize=(8, 4.5))
    ax = fig.add_subplot()
    ax.barh(labels, verified, color="#2ca02c", label="verified")
    ax.barh(labels, unverified, left=verified, color="#d9d9d9", label="unverified")
    for row, (v, t) in enumerate(zip(verified, total, strict=True)):
        if t:
            ax.text(t, row, f" {100 * v / t:.0f}%", va="center", fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("samples (clean view)")
    ax.set_title("Manual verification progress")
    ax.legend(loc="lower right", fontsize=8)
    return _save(fig, path)


def make_figures(df: pd.DataFrame, facts: dict[str, PageFacts], out_dir: Path) -> list[Path]:
    """Create every figure in ``out_dir`` and return their paths (in FIGURE_NAMES order)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return [
        figure_label_distribution(df, out_dir / FIGURE_NAMES[0]),
        figure_label_language_heatmap(df, out_dir / FIGURE_NAMES[1]),
        figure_quality_flags(df, out_dir / FIGURE_NAMES[2]),
        figure_text_length(df, facts, out_dir / FIGURE_NAMES[3]),
        figure_timeline(df, out_dir / FIGURE_NAMES[4]),
        figure_verification(df, out_dir / FIGURE_NAMES[5]),
    ]


def write_report(
    stats: dict[str, Any], df: pd.DataFrame, facts: dict[str, PageFacts], out_dir: Path
) -> list[Path]:
    """Write dataset_stats.json, dataset_stats.md and figures/*.png. Returns all paths."""
    figures = make_figures(df, facts, out_dir / "figures")
    stats = {**stats, "figures": [f"figures/{path.name}" for path in figures]}
    json_path, md_path = out_dir / "dataset_stats.json", out_dir / "dataset_stats.md"
    write_json(stats, json_path)
    md_path.write_text(render_markdown(stats, figures), encoding="utf-8")
    return [json_path, md_path, *figures]
