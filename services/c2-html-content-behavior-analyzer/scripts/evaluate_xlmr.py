"""Evaluate the imported XLM-R models once (per language + macro) and print the ablation.

Part 6: XLM-R content classification (6A, page level).
Thin CLI wrapper - all logic lives in ``c2_analyzer.nlp.evaluate``.

    python scripts/evaluate_xlmr.py --version v0.3            # -> reports/xlmr/v0.3/
    python scripts/evaluate_xlmr.py --version v0.3 --ablation-only

Without an imported XLM-R model only the ablation table (DOM-only, Behavior-only,
TF-IDF text) is printed, with XLM-R marked "not trained yet".
"""

from __future__ import annotations

import argparse
import sys

from c2_analyzer.nlp.common import XlmrConfig
from c2_analyzer.nlp.dataset import build_examples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--ablation-only", action="store_true")
    parser.add_argument("--no-figures", action="store_true")
    parser.add_argument(
        "--colab-seeds",
        action="store_true",
        help="score non-final seeds from their Colab predictions even if weights exist",
    )
    args = parser.parse_args(argv)
    config = XlmrConfig.load()
    data = build_examples(args.version)

    from c2_analyzer.nlp.evaluate import StaleModelError, ablation, evaluate_xlmr

    status = 0
    if not args.ablation_only:
        try:
            results = evaluate_xlmr(
                args.version,
                config,
                data,
                figures=not args.no_figures,
                local_seeds=not args.colab_seeds,
            )
        except FileNotFoundError as error:
            print(f"XLM-R: {error}")
        except StaleModelError as error:
            print(f"XLM-R model is STALE: {error}", file=sys.stderr)
            status = 1
        else:
            final, summary = results["models"]["final"], results["seed_summary"]["test"]
            print(
                f"XLM-R final (seed {results['final_seed']}): TEST macro-F1 "
                f"{final['test']['macro_f1']:.3f}, benign FPR "
                f"{100 * final['test']['benign_fpr']:.1f} %; {summary['n_seeds']} seeds: "
                f"{summary['mean']['macro_f1']:.3f} ± {summary['std']['macro_f1']:.3f}"
            )
            if results.get("consistency"):
                c = results["consistency"]
                verdict = "PASS" if c["ok"] else "CHECK"
                print(
                    f"Colab vs local CPU: labels identical {100 * c['argmax_agreement']:.1f} %, "
                    f"max |Δp| {c['max_abs_diff']} (< {c['tolerance']}) -> {verdict}"
                )
            print(f"reports: {config.reports_dir(args.version)}")
    _, _, text = ablation(args.version, config, data)
    print(f"\nAblation so far ({args.version}, same {data.meta['counts']['test']} test pages):")
    print(text)
    print(f"\nwritten: {config.reports_dir(args.version) / 'ablation.md'}")
    return status


if __name__ == "__main__":
    sys.exit(main())
