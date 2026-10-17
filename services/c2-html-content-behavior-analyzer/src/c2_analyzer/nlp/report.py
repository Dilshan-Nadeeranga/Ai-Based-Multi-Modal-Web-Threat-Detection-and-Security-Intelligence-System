"""Markdown + CSV writers of the Part 6A text models and the ablation table.

Part 6: XLM-R content classification (6A, page level).

One renderer for both text arms (TF-IDF results have ``cv``, XLM-R results have
``val`` and a seed summary), so their reports look alike. ``ablation_rows`` reads the
four arms' results.json files - DOM-only (Part 4), Behavior-only (Part 8), TF-IDF
text and XLM-R text - and refuses to call two arms comparable unless their split
fingerprints are equal (= the same 68 test pages).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd

from c2_analyzer.classifiers.dom_baseline.evaluate import confusion_text
from c2_analyzer.utils.io import atomic_write_text


def write_csv(frame: pd.DataFrame, path: Path) -> None:
    buffer = io.StringIO()
    frame.to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), Path(path))


def _num(value) -> str:
    return "—" if value is None else f"{value:.3f}"


def _pct(value) -> str:
    return "—" if value is None else f"{100 * value:.1f} %"


def _pm(mean, std) -> str:
    return "—" if mean is None else f"{mean:.3f} ± {std:.3f}"


def _pm_pct(mean, std) -> str:
    return "—" if mean is None else f"{100 * mean:.1f} ± {100 * std:.1f} %"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines + [""]


def _metric_row(name: str, score: str, m: dict) -> list[str]:
    return [
        name,
        score,
        _num(m.get("macro_precision")),
        _num(m.get("macro_recall")),
        f"**{_num(m.get('macro_f1'))}**",
        _num(m.get("weighted_f1")),
        _num(m.get("accuracy")),
        _pct(m.get("benign_fpr")),
        _num(m.get("roc_auc_ovr_macro")),
    ]


METRIC_HEADERS = [
    "model",
    "selection score",
    "macro-P",
    "macro-R",
    "macro-F1",
    "weighted-F1",
    "accuracy",
    "benign FPR",
    "ROC-AUC OvR",
]


def render_results_md(results: dict) -> str:
    """results.md of a text arm (TF-IDF baseline or XLM-R)."""
    labels = results["classes"]
    split = results.get("split", {})
    lines = [
        f"# {results.get('arm', 'text model')} - {results['version']}",
        "",
        f"- created: {results['created_at']}",
        f"- split fingerprint: `{split.get('split_fingerprint')}` "
        f"(train/val/test = {split.get('counts')})",
        f"- input: Part 5A page_text ({results.get('text_schema_version')}, rules "
        f"`{(results.get('text_rules_hash') or '')[:12]}`)",
        f"- selection: {results.get('selection')}",
        "",
    ]
    if results.get("smoke"):
        lines += [
            "> **SMOKE RUN** - tiny random model, 1 training step: these numbers only prove "
            "that the pipeline runs. They are not results.",
            "",
        ]
    lines += [
        "## Test results (evaluated once)",
        "",
    ]
    rows = []
    for name, model in results["models"].items():
        if "cv" in model:
            score = "CV " + _pm(model["cv"]["mean"]["macro_f1"], model["cv"]["std"]["macro_f1"])
        else:
            score = "val " + _num((model.get("val") or {}).get("macro_f1"))
        rows.append(_metric_row(model.get("display_name", name), score, model["test"]))
    summary = results.get("seed_summary")
    if summary:
        for split_name in ("val", "test"):
            s = summary[split_name]
            rows.append(
                [
                    f"mean ± std over {s['n_seeds']} seeds ({split_name})",
                    "",
                    _pm(s["mean"]["macro_precision"], s["std"]["macro_precision"]),
                    _pm(s["mean"]["macro_recall"], s["std"]["macro_recall"]),
                    f"**{_pm(s['mean']['macro_f1'], s['std']['macro_f1'])}**",
                    _pm(s["mean"]["weighted_f1"], s["std"]["weighted_f1"]),
                    _pm(s["mean"]["accuracy"], s["std"]["accuracy"]),
                    _pm_pct(s["mean"]["benign_fpr"], s["std"]["benign_fpr"]),
                    _pm(s["mean"]["roc_auc_ovr_macro"], s["std"]["roc_auc_ovr_macro"]),
                ]
            )
    lines += _table(METRIC_HEADERS, rows)

    best = results["models"][results["best_model"]]
    test = best["test"]
    lines += [f"## Per class - {best.get('display_name', results['best_model'])} (test)", ""]
    lines += _table(
        ["class", "precision", "recall", "F1", "support"],
        [
            [label, _num(c["precision"]), _num(c["recall"]), _num(c["f1"]), c["support"]]
            for label, c in test["per_class"].items()
        ],
    )
    languages = best["per_language"]
    languages = languages.get("test", languages)
    lines += ["## Per language (test; Part 5A detected language)", ""]
    lines += _table(
        ["language", "n", "macro-P", "macro-R", "macro-F1", "accuracy", "benign FPR", "labels"],
        [
            [
                lang + (" ⚠ small n" if row.get("small_n") and row["n"] else ""),
                row["n"],
                _num(row.get("macro_precision")),
                _num(row.get("macro_recall")),
                _num(row.get("macro_f1")),
                _num(row.get("accuracy")),
                _pct(row.get("benign_fpr")),
                ", ".join(f"{k} {v}" for k, v in (row.get("labels") or {}).items()) or "—",
            ]
            for lang, row in languages.items()
        ],
    )
    lines += [
        "Per-language macro scores average over the classes present in that language; "
        "with fewer test pages than the small-n limit they are anecdotes, not estimates.",
        "",
        "## Confusion matrix (test, rows = true)",
        "",
        "```",
        confusion_text(test["confusion_matrix"], labels),
        "```",
        "",
        f"Benign test pages flagged as a threat: {len(best.get('benign_false_positives', []))}"
        + (
            f" ({', '.join(best['benign_false_positives'])})"
            if best.get("benign_false_positives")
            else ""
        ),
        "",
    ]
    if best.get("top_ngrams"):
        lines += ["## Strongest character n-grams per class (LR coefficients)", ""]
        lines += _table(
            ["class", "n-grams"],
            [[c, " · ".join(f"`{g}`" for g in grams)] for c, grams in best["top_ngrams"].items()],
        )
    consistency = results.get("consistency")
    if consistency:
        lines += [
            "## Colab vs local CPU (final model)",
            "",
            f"- predicted labels identical: {_pct(consistency.get('argmax_agreement'))} of "
            f"{consistency.get('n')} pages; max |Δ probability| = "
            f"{consistency.get('max_abs_diff')} (must be < {consistency.get('tolerance')}) → "
            f"**{'PASS' if consistency.get('ok') else 'CHECK'}**",
            "- rule: PASS if every label is identical and max |Δp| < the tolerance; GPU vs "
            "CPU fp32 differences of ~1e-3 are expected.",
            "",
        ]
    return "\n".join(lines)


# ---- ablation --------------------------------------------------------------------------------


def _best_entry(results: dict) -> tuple[str, dict]:
    name = results.get("best_model")
    return name, results["models"][name]


def ablation_rows(paths: dict[str, Path], reference_fingerprint: str | None) -> list[dict]:
    """One row per arm whose results.json exists (``paths``: arm -> results.json)."""
    rows = []
    for arm, path in paths.items():
        path = Path(path)
        if not path.is_file():
            rows.append({"arm": arm, "available": False, "path": str(path)})
            continue
        results = json.loads(path.read_text(encoding="utf-8"))
        name, model = _best_entry(results)
        fingerprint = (results.get("split") or {}).get("split_fingerprint")
        summary = results.get("seed_summary")
        if "cv" in model:
            label, mean, std = "CV", model["cv"]["mean"]["macro_f1"], model["cv"]["std"]["macro_f1"]
        elif summary:
            label = f"{summary['test']['n_seeds']}-seed test"
            mean = summary["test"]["mean"]["macro_f1"]
            std = summary["test"]["std"]["macro_f1"]
        else:
            label, mean, std = "—", None, None
        rows.append(
            {
                "arm": arm,
                "available": True,
                "model": model.get("display_name", name),
                "score_label": label,
                "score_mean": mean,
                "score_std": std,
                "test_macro_f1": model["test"]["macro_f1"],
                "benign_fpr": model["test"]["benign_fpr"],
                "per_class_f1": {k: v["f1"] for k, v in model["test"]["per_class"].items()},
                "n_test": model["test"]["n"],
                "split_fingerprint": fingerprint,
                "same_split": reference_fingerprint is not None
                and fingerprint == reference_fingerprint,
            }
        )
    return rows


def render_ablation_md(rows: list[dict], version: str, classes: list[str]) -> str:
    lines = [
        f"# Ablation so far - {version} (same test pages, macro-F1 primary)",
        "",
    ]
    table = []
    for row in rows:
        if not row["available"]:
            table.append([row["arm"], "not trained yet", "", "", "", ""] + [""] * len(classes))
            continue
        table.append(
            [
                row["arm"],
                row["model"],
                f"{row['score_label']} {_pm(row['score_mean'], row['score_std'])}",
                f"**{_num(row['test_macro_f1'])}**",
                _pct(row["benign_fpr"]),
                f"{row['n_test']}" + ("" if row["same_split"] else " ⚠ other split"),
            ]
            + [_num(row["per_class_f1"].get(c)) for c in classes]
        )
    lines += _table(
        ["arm", "model", "CV / seed mean ± std", "test macro-F1", "benign FPR", "n test"]
        + [f"F1 {c}" for c in classes],
        table,
    )
    lines += [
        "CV = grouped 5-fold over train+val (DOM, Behavior, TF-IDF; best model by CV). "
        "XLM-R = mean ± std of the test macro-F1 over its seeds; its 'test macro-F1' is "
        "the final model (seed chosen on val).",
        "",
    ]
    return "\n".join(lines)


def ablation_text(rows: list[dict], classes: list[str]) -> str:
    """Plain-text version for the terminal."""
    head = f"{'arm':<20}{'model':<28}{'CV/seed mean±std':<24}{'test F1':>8}{'ben.FPR':>9}"
    head += "".join(f"{c[:10]:>11}" for c in classes)
    lines = [head, "-" * len(head)]
    for row in rows:
        if not row["available"]:
            lines.append(f"{row['arm']:<20}not trained yet")
            continue
        score = f"{row['score_label']} {_pm(row['score_mean'], row['score_std'])}"
        line = f"{row['arm']:<20}{row['model'][:27]:<28}{score:<24}"
        line += f"{_num(row['test_macro_f1']):>8}{_pct(row['benign_fpr']):>9}"
        line += "".join(f"{_num(row['per_class_f1'].get(c)):>11}" for c in classes)
        if not row["same_split"]:
            line += "  (other split!)"
        lines.append(line)
    return "\n".join(lines)
