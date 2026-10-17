"""Ablation report: reports/ablation/<v>/ (ablation.md / .json, test_predictions.csv, figures/).

Part 9: Tri-modal fusion + ablation study (Batch A, task 4).

Figures (matplotlib Figure API, never opens a window):
    macro_f1_ci.png        test macro-F1 with the bootstrap 95 % CI per row (+ CV mean)
    confusion_final.png    confusion matrix of the final fusion model (test, argmax)
    benign_fpr.png         benign FPR at argmax vs at the <= 2 % OOF threshold, per row
    explain_<strategy>.png arm shares + LR coefficients / top SHAP features
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from matplotlib.figure import Figure

from c2_analyzer.classifiers.dom_baseline.evaluate import confusion_text, plot_confusion_matrix
from c2_analyzer.fusion.explain import plot_explanation
from c2_analyzer.utils.io import atomic_write_csv, atomic_write_text, write_json

LANGUAGES = ["en", "si", "ta", "mixed", "other"]


def _num(value) -> str:
    return "—" if value is None else f"{value:.3f}"


def _pct(value) -> str:
    return "—" if value is None else f"{100 * value:.1f} %"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return lines + ["| " + " | ".join(row) + " |" for row in rows]


def table_entries(results: dict) -> list[dict]:
    """The main table: singles, each pair with its CV-chosen strategy, tri with all."""
    entries = results["entries"]
    return [
        e
        for e in entries
        if e["group"] == "single"
        or (e["group"] == "pair" and e.get("selected_for_row"))
        or e["group"] == "tri"
    ]


def _name(e: dict, final_key: str) -> str:
    title = e["title"] if e["group"] == "single" else f"{e['title']} · {e['strategy_display']}"
    return f"**{title}** ★" if e["key"] == final_key else title


def render_markdown(results: dict) -> str:
    final, labels = results["final"], results["classes"]
    rows = table_entries(results)
    displays = {arm: m.get("display", arm) for arm, m in results["arm_models"].items()}
    lines = [
        f"# Ablation study - {results['version']} (C2 Part 9A: tri-modal fusion)",
        "",
        f"- created: {results['created_at']}",
        f"- split fingerprint: `{results['split']['split_fingerprint']}`; pages: "
        f"train+val {results['split']['counts']['train+val']} (grouped 5-fold CV), "
        f"test {results['split']['counts']['test']} (used once)",
        f"- arms: {', '.join(displays.get(a, a) for a in results['arms_available'])}",
    ]
    if results["arms_missing"]:
        lines.append(
            f"- **not included: {', '.join(results['arms_missing'])}** - no OOF predictions "
            "yet (text_xlmr needs the Colab CV run: `train_xlmr.py export-bundle --cv` → "
            "notebook → `import-oof`). Every row and the fusion below run without it."
        )
    lines += [
        "- every choice (weights, stacker, final strategy, benign threshold) is made on "
        "grouped CV over train+val; the test pages are predicted once per row and only "
        "reported. CV = mean ± std over the 5 folds of the selected configuration.",
        "",
        "## Main table (test, argmax unless stated)",
        "",
    ]
    lines += _table(
        [
            "row",
            "CV macro-F1",
            "test macro-F1 [95 % CI]",
            "weighted-F1",
            "accuracy",
            "ROC-AUC",
            "benign FPR (argmax)",
            "benign FPR (≤ 2 % thr.)",
        ],
        [
            [
                _name(e, final["key"]),
                f"{e['cv']['mean']['macro_f1']:.3f} ± {e['cv']['std']['macro_f1']:.3f}",
                f"**{e['test']['macro_f1']:.3f}** [{e['bootstrap']['ci_low']:.3f}, "
                f"{e['bootstrap']['ci_high']:.3f}]",
                _num(e["test"]["weighted_f1"]),
                _num(e["test"]["accuracy"]),
                _num(e["test"]["roc_auc_ovr_macro"]),
                _pct(e["test"]["benign_fpr"]),
                _pct(e["operating_point"]["test"]["fpr_constrained"]["benign_fpr"]),
            ]
            for e in rows
        ],
    )
    lines += [
        "",
        f"★ final fusion model: **{final['title']} · {final['strategy_display']}** "
        f"(best tri-modal CV macro-F1 {final['cv']['mean']['macro_f1']:.3f}).",
        "",
        "## Per-class F1 (test)",
        "",
    ]
    lines += _table(
        ["row"] + labels,
        [
            [_name(e, final["key"])] + [_num(e["test"]["per_class"][c]["f1"]) for c in labels]
            for e in rows
        ],
    )
    lines += ["", "## Per-language accuracy (test; Part 5A detected language, n pages)", ""]
    counts = (
        {lang: rows[0]["per_language"].get(lang, {}).get("n", 0) for lang in LANGUAGES}
        if rows
        else {}
    )
    lines += _table(
        ["row"] + [f"{lang} (n={counts.get(lang, 0)})" for lang in LANGUAGES],
        [
            [_name(e, final["key"])]
            + [
                _num(e["per_language"].get(lang, {}).get("accuracy"))
                + (
                    " ⚠"
                    if e["per_language"].get(lang, {}).get("small_n") and counts.get(lang)
                    else ""
                )
                for lang in LANGUAGES
            ]
            for e in rows
        ],
    )
    lines += ["", "⚠ = fewer than 10 test pages: an anecdote, not an estimate.", ""]

    # operating point
    target = results["benign_fpr_target"]
    lines += [
        f"## Benign-FPR operating point (target ≤ {100 * target:.0f} %)",
        "",
        "Rule: benign if P(benign) ≥ t, else the most probable threat class; t = the largest "
        "threshold whose OUT-OF-FOLD benign FPR on train+val is ≤ the target (chosen without "
        "test). Threat recall = threat pages flagged as any threat.",
        "",
    ]
    lines += _table(
        [
            "row",
            "t",
            "OOF benign FPR",
            "test benign FPR argmax → thr.",
            "test threat recall argmax → thr.",
            "test macro-F1 argmax → thr.",
        ],
        [
            [
                _name(e, final["key"]),
                f"{e['operating_point']['threshold']:.3f}",
                _pct(e["operating_point"]["oof_benign_fpr"]),
                f"{_pct(op['argmax']['benign_fpr'])} → {_pct(op['fpr_constrained']['benign_fpr'])}",
                f"{_pct(op['argmax']['threat_recall'])} → "
                f"{_pct(op['fpr_constrained']['threat_recall'])}",
                f"{_num(op['argmax']['macro_f1'])} → {_num(op['fpr_constrained']['macro_f1'])}",
            ]
            for e in rows
            for op in [e["operating_point"]["test"]]
        ],
    )
    fc = final["operating_point"]["test"]["fpr_constrained"]
    lines += [
        "",
        "Final model at the threshold: confusion matrix (test, rows = true):",
        "",
        "```",
        confusion_text(fc["confusion_matrix"], labels),
        "```",
        "",
    ]

    # bootstrap comparison
    comparison, settings = results["comparison"], results["bootstrap_settings"]
    lines += [
        "## Tri-modal vs best single arm (paired bootstrap)",
        "",
        f"{settings['n_resamples']} resamples of the {results['split']['counts']['test']} test "
        f"pages (seed {settings['seed']}), the same resamples for every row; "
        f"{100 * settings['confidence']:.0f} % percentile CI of the macro-F1 DIFFERENCE.",
        "",
    ]
    for label, key in (
        ("best single arm by CV", "vs_best_single_by_cv"),
        ("best single arm on test (conservative)", "vs_best_single_on_test"),
    ):
        d = comparison[key]
        verdict = (
            "**the CI includes 0 - the test set cannot distinguish them** (small test set)"
            if d["includes_zero"]
            else "the CI excludes 0"
        )
        lines.append(
            f"- final − {label} (`{d['single']}`): **{d['point']:+.3f}** "
            f"[{d['ci_low']:+.3f}, {d['ci_high']:+.3f}]; final better in "
            f"{100 * d['share_a_better']:.1f} % of resamples → {verdict}."
        )

    # complementarity
    comp = results["complementarity"]
    lines += [
        "",
        f"## Complementarity (test, argmax; text = `{comp.get('text_arm')}`)",
        "",
        f"Oracle (any modality right): {_pct(comp['oracle_accuracy'])} of "
        f"{comp['n']} pages vs final fusion accuracy {_pct(final['test']['accuracy'])}.",
        "",
    ]
    lines += _table(
        ["bucket", "pages", "final fusion right", "examples"],
        [
            [
                bucket.replace("_", " "),
                str(entry["count"]),
                str(entry.get("fusion_right", "—")),
                ", ".join(f"`{i}`" for i in entry["examples"]),
            ]
            for bucket, entry in comp["buckets"].items()
        ],
    )

    # explanations
    lines += ["", "## Explainability (test pages)", ""]
    for strategy, explanation in results["explanations"].items():
        shares = ", ".join(
            f"{displays.get(arm, arm)} {100 * share:.0f} %"
            for arm, share in sorted(explanation["arm_share"].items(), key=lambda kv: -kv[1])
        )
        lines.append(f"- **{strategy}** ({explanation['method']}): {shares}")
        for feature in explanation.get("top_features", [])[:10]:
            lines.append(f"  - `{feature['feature']}` mean |SHAP| {feature['mean_abs_shap']:.3f}")
    lines.append("")

    # every pair strategy
    pairs = [e for e in results["entries"] if e["group"] == "pair"]
    if pairs:
        lines += ["## Pairs: every strategy (✓ = chosen by CV)", ""]
        lines += _table(
            ["pair", "strategy", "CV macro-F1", "test macro-F1", "benign FPR"],
            [
                [
                    e["title"],
                    e["strategy_display"] + (" ✓" if e.get("selected_for_row") else ""),
                    f"{e['cv']['mean']['macro_f1']:.3f} ± {e['cv']['std']['macro_f1']:.3f}",
                    _num(e["test"]["macro_f1"]),
                    _pct(e["test"]["benign_fpr"]),
                ]
                for e in pairs
            ],
        )
        lines.append("")

    lines += ["## Arm models (OOF = other folds; test = final model on train+val)", ""]
    for arm, m in results["arm_models"].items():
        reproduced = m.get("reproduces_part_oof")
        lines.append(
            f"- **{m.get('display', arm)}**: {m.get('part')} {m.get('model_display')} "
            f"{m.get('params', '')}"
            + ("" if reproduced is None else f" - reproduces the Part's CV: {reproduced}")
        )
    lines += [
        "",
        "## Notes",
        "",
        "- Stacking / weighted / hybrid are fit inside each CV fold on the other folds' "
        "pages; the arm OOF probabilities they read for those pages came from arm models "
        "that saw the held-out fold (standard stacking, not fully nested).",
        "- The CV score of a selected configuration is slightly optimistic (it won a "
        "comparison on the same folds); the test score is the unbiased one, but on 68 pages.",
        "",
    ]
    return "\n".join(lines)


# ---- figures -----------------------------------------------------------------------------------


def plot_macro_f1(rows: list[dict], final_key: str, path: Path) -> Path:
    names = [_name(e, final_key).replace("**", "") for e in rows][::-1]
    points = np.array([e["test"]["macro_f1"] for e in rows][::-1])
    low = points - np.array([e["bootstrap"]["ci_low"] for e in rows][::-1])
    high = np.array([e["bootstrap"]["ci_high"] for e in rows][::-1]) - points
    cv = [e["cv"]["mean"]["macro_f1"] for e in rows][::-1]
    figure = Figure(figsize=(10, 0.45 * len(rows) + 1.6), layout="constrained")
    axis = figure.subplots()
    y = np.arange(len(rows))
    colors = ["#c0392b" if "★" in n else "#3b6fb6" for n in names]
    axis.barh(y, points, xerr=[low, high], color=colors, alpha=0.8, capsize=3, label="test")
    axis.scatter(cv, y, marker="D", color="black", zorder=3, s=18, label="CV mean")
    axis.set_yticks(y, names, fontsize=8)
    axis.set_xlim(0, 1)
    axis.set_xlabel("macro-F1 (test, bootstrap 95 % CI)")
    axis.legend(loc="lower right", fontsize=8)
    axis.set_title("Ablation: test macro-F1 per row (★ = final fusion model)")
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def plot_benign_fpr(rows: list[dict], final_key: str, target: float, path: Path) -> Path:
    names = [_name(e, final_key).replace("**", "") for e in rows]
    argmax = [100 * (e["test"]["benign_fpr"] or 0) for e in rows]
    constrained = [
        100 * (e["operating_point"]["test"]["fpr_constrained"]["benign_fpr"] or 0) for e in rows
    ]
    figure = Figure(figsize=(max(8, 0.9 * len(rows) + 2), 4.8), layout="constrained")
    axis = figure.subplots()
    x = np.arange(len(rows))
    axis.bar(x - 0.2, argmax, 0.4, label="argmax")
    axis.bar(x + 0.2, constrained, 0.4, label=f"threshold (OOF FPR ≤ {100 * target:.0f} %)")
    axis.axhline(100 * target, color="red", linestyle="--", linewidth=1, label="target")
    axis.set_xticks(x, names, rotation=35, ha="right", fontsize=7)
    axis.set_ylabel("benign FPR on test (%)")
    axis.set_title("Benign pages flagged as a threat (test)")
    axis.legend(fontsize=8)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def write_reports(results: dict, entries: list[dict], data, folder: Path, figures: bool = True):
    from c2_analyzer.fusion.ablation import test_predictions_frame

    folder = Path(folder)
    write_json(results, folder / "ablation.json")
    atomic_write_text(render_markdown(results), folder / "ablation.md")
    by_key = {e["key"]: e for e in entries}
    frame = test_predictions_frame(entries, data, by_key[results["final"]["key"]])
    atomic_write_csv(frame, folder / "test_predictions.csv", list(frame.columns))
    if not figures:
        return
    final = results["final"]
    rows = table_entries(results)
    plot_macro_f1(rows, final["key"], folder / "figures" / "macro_f1_ci.png")
    plot_benign_fpr(
        rows, final["key"], results["benign_fpr_target"], folder / "figures" / "benign_fpr.png"
    )
    plot_confusion_matrix(
        final["test"]["confusion_matrix"],
        results["classes"],
        f"Final fusion ({final['strategy_display']}) - test ({results['version']})",
        folder / "figures" / "confusion_final.png",
    )
    displays = {arm: m.get("display", arm) for arm, m in results["arm_models"].items()}
    for strategy, explanation in results["explanations"].items():
        plot_explanation(
            explanation,
            displays,
            f"Fusion explanation - {strategy} ({results['version']}, test pages)",
            folder / "figures" / f"explain_{strategy}.png",
        )
