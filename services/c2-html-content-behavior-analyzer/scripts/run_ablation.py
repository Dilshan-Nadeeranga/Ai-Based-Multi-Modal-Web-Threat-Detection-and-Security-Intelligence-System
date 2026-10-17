"""Part 9A: out-of-fold predictions per arm, tri-modal fusion and the ablation study.

Part 9: Tri-modal fusion + ablation study (Batch A).
Thin CLI wrapper - all logic lives in ``c2_analyzer.fusion``.

    python scripts/run_ablation.py --version v0.3                # OOF (dom, behavior, tfidf) + all
    python scripts/run_ablation.py --version v0.3 --reuse-oof    # keep the stored OOF tables
    python scripts/run_ablation.py --version v0.3 --oof-only

text_xlmr is used when data/processed/fusion/<v>/oof_text_xlmr.csv exists (made by
``train_xlmr.py import-oof`` after the Colab CV run); otherwise the study runs without it.
Outputs: data/processed/fusion/<v>/, models/fusion/<v>/, reports/ablation/<v>/.
"""

from __future__ import annotations

import argparse
import sys
import time

from c2_analyzer.fusion.common import FusionConfig


def _pct(value) -> str:
    return "—" if value is None else f"{100 * value:.1f} %"


def print_summary(results: dict) -> None:
    from c2_analyzer.fusion.report import table_entries

    final = results["final"]
    print(f"\nABLATION - {results['version']} (test n={results['split']['counts']['test']})")
    if results["arms_missing"]:
        print(f"NOT included (no OOF yet): {', '.join(results['arms_missing'])}")
    header = (
        f"{'row':<62} {'CV macro-F1':>14} {'test F1':>8} {'95 % CI':>15} "
        f"{'acc':>6} {'AUC':>6} {'FPR':>7} {'FPR@t':>7}"
    )
    print(header)
    print("-" * len(header))
    for e in table_entries(results):
        name = e["title"] if e["group"] == "single" else f"{e['title']} · {e['strategy_display']}"
        if e["key"] == final["key"]:
            name = "* " + name
        auc = e["test"]["roc_auc_ovr_macro"]
        print(
            f"{name[:62]:<62} {e['cv']['mean']['macro_f1']:.3f} ± {e['cv']['std']['macro_f1']:.3f} "
            f"{e['test']['macro_f1']:>8.3f} [{e['bootstrap']['ci_low']:.3f}, "
            f"{e['bootstrap']['ci_high']:.3f}] {e['test']['accuracy']:>6.3f} "
            f"{'—' if auc is None else f'{auc:.3f}':>6} {_pct(e['test']['benign_fpr']):>7} "
            f"{_pct(e['operating_point']['test']['fpr_constrained']['benign_fpr']):>7}"
        )
    print(
        f"\nFINAL fusion model (best tri-modal CV): {final['title']} · "
        f"{final['strategy_display']} - CV {final['cv']['mean']['macro_f1']:.3f}, "
        f"test macro-F1 {final['test']['macro_f1']:.3f}"
    )
    op = final["operating_point"]
    t = op["test"]
    print(
        f"FPR operating point: t = {op['threshold']:.3f} (OOF benign FPR "
        f"{_pct(op['oof_benign_fpr'])}, target {_pct(op['target'])})"
    )
    print(
        f"  test argmax:    benign FPR {_pct(t['argmax']['benign_fpr'])}, threat recall "
        f"{_pct(t['argmax']['threat_recall'])}, macro-F1 {t['argmax']['macro_f1']:.3f}"
    )
    print(
        f"  test threshold: benign FPR {_pct(t['fpr_constrained']['benign_fpr'])}, threat recall "
        f"{_pct(t['fpr_constrained']['threat_recall'])}, macro-F1 "
        f"{t['fpr_constrained']['macro_f1']:.3f}"
    )
    for label, key in (
        ("best single (CV)", "vs_best_single_by_cv"),
        ("best single (test)", "vs_best_single_on_test"),
    ):
        d = results["comparison"][key]
        print(
            f"final - {label} [{d['single']}]: {d['point']:+.3f}, 95 % CI "
            f"[{d['ci_low']:+.3f}, {d['ci_high']:+.3f}] -> "
            + (
                "CI INCLUDES 0 (not distinguishable on 68 pages)"
                if d["includes_zero"]
                else "CI excludes 0"
            )
        )
    comp = results["complementarity"]
    print(
        f"complementarity (text = {comp['text_arm']}), "
        f"oracle accuracy {_pct(comp['oracle_accuracy'])}:"
    )
    for bucket, entry in comp["buckets"].items():
        print(
            f"  {bucket:<22} {entry['count']:>3}  (fusion right {entry.get('fusion_right', '-')})  "
            f"e.g. {', '.join(entry['examples'])}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--reuse-oof", action="store_true", help="do not rebuild local OOF tables")
    parser.add_argument("--oof-only", action="store_true", help="only build the OOF tables")
    parser.add_argument("--no-figures", action="store_true")
    args = parser.parse_args(argv)
    config = FusionConfig.load()
    started = time.perf_counter()

    from c2_analyzer.fusion.oof import build_oof, oof_paths

    if not args.reuse_oof or not all(
        oof_paths(config.oof_dir(args.version), arm)[0].is_file()
        for arm in ("dom", "behavior", "text_tfidf")
    ):
        build_oof(args.version, config=config)
    if args.oof_only:
        print(f"OOF tables: {config.oof_dir(args.version)}")
        return 0

    from c2_analyzer.fusion.ablation import run_ablation

    results = run_ablation(args.version, config, figures=not args.no_figures)
    print_summary(results)
    print(f"\ndone in {time.perf_counter() - started:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
