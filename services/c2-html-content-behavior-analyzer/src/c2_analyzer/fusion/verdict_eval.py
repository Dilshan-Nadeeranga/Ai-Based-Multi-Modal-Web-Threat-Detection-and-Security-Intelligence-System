"""Operating points of the verdict policy: OOF (train+val) and once on the 68 test pages.

Part 9: Batch B-1 - end-to-end URL analysis engine.

Reported honestly, for (a) the fusion tiers alone and (b) tiers + evidence floor:
- benign FPR   = benign pages flagged Suspicious or Malicious (and Malicious only)
- threat recall = threat pages flagged Suspicious or Malicious (and Malicious only)
- threat-class accuracy among the flagged threat pages

OOF: the 391 train+val pages, fused exactly as the thresholds were chosen (calibration.py)
- this is where the thresholds come from, so these numbers are the DESIGN targets, not a
held-out estimate. Floor evidence = the stored Part 3 / Part 8 results of each page.

TEST: the 68 test pages run through the LIVE engine (``Orchestrator.analyze`` in html
mode with the page URL, exactly what the API does), with and without XLM-R, once. The
same run gives the latency (p50 / p95, warm models) and a parity check: the live arm
probabilities must equal the 9A stored test probabilities (same final arm models), and
the live fused probabilities the 9A fused test predictions.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import numpy as np

from c2_analyzer.config import resolve_path
from c2_analyzer.fusion.calibration import fold_models, fuse_arms, oof_for_subset
from c2_analyzer.fusion.common import FusionConfig
from c2_analyzer.fusion.verdict import VerdictPolicy, decide, floor_hits
from c2_analyzer.schemas.analysis import AnalysisRequest
from c2_analyzer.schemas.behavior import BehaviorResult
from c2_analyzer.schemas.dom import DomResult


def tier_metrics(labels: list[str], rows: list[dict], key: str) -> dict:
    """rows: {"label", <key>: (verdict | None, threat_class | None)}."""
    benign = [r for r in rows if r["label"] == "benign"]
    threats = [r for r in rows if r["label"] != "benign"]

    def share(items, test) -> float | None:
        return float(np.mean([test(r) for r in items])) if items else None

    flagged = lambda r: r[key][0] in ("Suspicious", "Malicious")  # noqa: E731
    malicious = lambda r: r[key][0] == "Malicious"  # noqa: E731
    caught = [r for r in threats if flagged(r)]
    per_class = {
        label: share([r for r in threats if r["label"] == label], flagged)
        for label in labels
        if label != "benign"
    }
    return {
        "n_benign": len(benign),
        "n_threat": len(threats),
        "benign_fpr_flagged": share(benign, flagged),
        "benign_fpr_malicious": share(benign, malicious),
        "threat_recall_flagged": share(threats, flagged),
        "threat_recall_malicious": share(threats, malicious),
        "threat_class_accuracy": share(caught, lambda r: r[key][1] == r["label"]),
        "no_verdict": sum(1 for r in rows if r[key][0] is None),
        "recall_per_class": per_class,
    }


def _stored(folder: Path, sample_id: str, model):
    path = folder / f"{sample_id}.json"
    return model.model_validate_json(path.read_text(encoding="utf-8")) if path.is_file() else None


def page_hits(policy: VerdictPolicy, version: str, sample_id: str):
    """Floor rules for a dataset page from its stored Part 3 / Part 8 results."""
    data_dir = resolve_path(Path("data")) / "processed"
    dom = _stored(data_dir / "dom_features" / version, sample_id, DomResult)
    behavior = _stored(data_dir / "behavior" / version, sample_id, BehaviorResult)
    return floor_hits(
        policy.rules,
        dom_features=dict(dom.features) if dom else None,
        behavior_findings=(
            [(f.pattern_id, f.variant, None) for f in behavior.findings] if behavior else None
        ),
    )


def evaluate_oof(version: str, configs: dict[str, list[str]], log=print) -> dict:
    """Tier metrics on the OOF fused probabilities, per arm configuration."""
    from c2_analyzer.fusion.data import FusionData
    from c2_analyzer.fusion.model import load_bundle

    config = FusionConfig.load()
    policy = VerdictPolicy.load()
    bundle = load_bundle(config.models_dir(version))
    data = FusionData.load(version, config)
    labels = data.labels
    models, inputs = fold_models(data, bundle, config)
    ids, y, folds = data.ids("pool"), data.y("pool"), data.folds()
    hits = {sample_id: page_hits(policy, version, sample_id) for sample_id in ids}
    fired: dict[str, dict[str, int]] = {
        rule.id: {"benign": 0, "threat": 0} for rule in policy.rules
    }
    for sample_id, label in zip(ids, y, strict=True):
        for hit in {h.rule.id for h in hits[sample_id]}:
            fired[hit]["benign" if labels[int(label)] == "benign" else "threat"] += 1
    out = {"rules_fired": fired}
    for name, arms in configs.items():
        oof = oof_for_subset(models, inputs, folds, arms)
        thresholds = policy.for_arms(arms)
        rows = []
        for sample_id, label, p in zip(ids, y, oof, strict=True):
            probs = {c: float(v) for c, v in zip(labels, p, strict=True)}
            fusion = decide(probs, thresholds, [])
            final = decide(probs, thresholds, hits[sample_id])
            rows.append(
                {
                    "sample_id": sample_id,
                    "label": labels[int(label)],
                    "fusion": (fusion.verdict, fusion.threat_class),
                    "floor": (final.verdict, final.threat_class),
                    "raised": bool(final.raised_by),
                }
            )
        out[name] = {
            "arms": arms,
            "thresholds": thresholds.as_dict(),
            "fusion_only": tier_metrics(labels, rows, "fusion"),
            "with_floor": tier_metrics(labels, rows, "floor"),
            "floor_raised": _raised(rows),
        }
        log(f"OOF {name}: done")
    return out


def _raised(rows: list[dict]) -> dict:
    raised = [r for r in rows if r["raised"]]
    return {
        "benign_pages": sum(1 for r in raised if r["label"] == "benign"),
        "threat_pages": sum(1 for r in raised if r["label"] != "benign"),
        "benign_examples": [r["sample_id"] for r in raised if r["label"] == "benign"][:5],
    }


def evaluate_test(version: str, xlmr: bool, log=print) -> dict:
    """The live engine on every test page (html mode), once. Latency + parity included."""
    from c2_analyzer.api.dev_data import DevDataset
    from c2_analyzer.fusion.data import FusionData
    from c2_analyzer.fusion.orchestrator import Orchestrator, ServingModels

    started = time.perf_counter()
    orchestrator = Orchestrator(ServingModels.load(version, xlmr_enabled=xlmr))
    load_s = time.perf_counter() - started
    models = orchestrator.models
    if models.problems:
        raise RuntimeError("; ".join(models.problems))
    data = FusionData.load(version, models.fusion_config)
    dataset = DevDataset.from_settings()
    test_ids, y = data.ids("test"), data.y("test")
    labels = data.labels
    arms = [a for a in models.fusion_arms if xlmr or a != "text_xlmr"]
    stored_fused = fuse_arms(models.fusion_model, data.inputs(arms, test_ids), arms)
    thresholds = models.policy.for_arms(arms)

    # one warm-up page (first-call allocations), not timed
    html, url = dataset.raw_html(version, test_ids[0])
    orchestrator.analyze(AnalysisRequest(html=html, url=url))

    rows, latency, arm_diff, fused_diff, statuses = [], [], {a: 0.0 for a in arms}, 0.0, {}
    for index, (sample_id, label) in enumerate(zip(test_ids, y, strict=True)):
        html, url = dataset.raw_html(version, sample_id)
        tick = time.perf_counter()
        result = orchestrator.analyze(AnalysisRequest(html=html, url=url, request_id=sample_id))
        latency.append((time.perf_counter() - tick) * 1000)
        statuses[result.status] = statuses.get(result.status, 0) + 1
        arm_results = {
            a.arm: a
            for m in (result.modalities.dom, result.modalities.content, result.modalities.behavior)
            for a in m.arms
        }
        for arm in arms:
            live = arm_results.get(arm)
            if live is not None and live.probabilities:
                stored = data.oofs[arm].proba([sample_id])[0]
                vector = np.array([live.probabilities[c] for c in labels])
                arm_diff[arm] = max(arm_diff[arm], float(np.abs(vector - stored).max()))
        if result.class_probabilities:
            vector = np.array([result.class_probabilities[c] for c in labels])
            fused_diff = max(fused_diff, float(np.abs(vector - stored_fused[index]).max()))
        # (a) the fusion tiers alone, on the live fused probabilities of this page
        fusion = None
        if result.class_probabilities and result.status == "ok":
            fusion = decide(result.class_probabilities, thresholds, [])
        rows.append(
            {
                "sample_id": sample_id,
                "label": labels[int(label)],
                "fusion": (fusion.verdict, fusion.threat_class) if fusion else (None, None),
                "floor": (result.verdict, result.threat_class),
                "raised": result.explanation.verdict_source == "evidence_floor",
                "status": result.status,
                "risk": result.risk_score,
                "language": result.page_language,
            }
        )
        if (index + 1) % 17 == 0:
            log(f"  test {'with' if xlmr else 'without'} XLM-R: {index + 1}/{len(test_ids)}")
    lat = np.array(latency)
    return {
        "xlmr": xlmr,
        "arms": arms,
        "thresholds": thresholds.as_dict(),
        "load_seconds": round(load_s, 1),
        "latency_ms": {
            "p50": round(float(np.percentile(lat, 50)), 1),
            "p95": round(float(np.percentile(lat, 95)), 1),
            "mean": round(float(lat.mean()), 1),
            "max": round(float(lat.max()), 1),
        },
        "statuses": statuses,
        "parity": {
            "max_abs_diff_per_arm": {k: round(v, 6) for k, v in arm_diff.items()},
            "max_abs_diff_fused": round(fused_diff, 6),
        },
        "fusion_only": tier_metrics(labels, rows, "fusion"),
        "with_floor": tier_metrics(labels, rows, "floor"),
        "floor_raised": _raised(rows),
        "pages": rows,
    }


# ---- report --------------------------------------------------------------------------------


def _pct(value) -> str:
    return "—" if value is None else f"{100 * value:.1f} %"


def _row(name: str, m: dict) -> str:
    return (
        f"| {name} | {_pct(m['benign_fpr_flagged'])} | {_pct(m['benign_fpr_malicious'])} | "
        f"{_pct(m['threat_recall_flagged'])} | {_pct(m['threat_recall_malicious'])} | "
        f"{_pct(m['threat_class_accuracy'])} |"
    )


HEADER = (
    "| policy | benign FPR (flagged) | benign → Malicious | threat recall (flagged) | "
    "threat recall (Malicious) | threat-class acc. (flagged threats) |\n|---|---|---|---|---|---|"
)


def markdown(version: str, oof: dict, tests: list[dict], calibration: dict) -> str:
    lines = [
        f"# Verdict operating points - {version} (C2 Part 9 B-1)",
        "",
        f"- created: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- fusion: {calibration.get('fusion_strategy')} "
        f"{calibration.get('fusion_weights')}; thresholds calibrated "
        f"{calibration.get('created_at')} (reproduces 9A threshold: "
        f"{calibration.get('reproduces_9a_threshold')})",
        "- flagged = Suspicious or Malicious. (a) fusion tiers only, (b) tiers + evidence floor.",
        "",
        "## How the thresholds were chosen",
        "",
        "On the 391 train+val pages' OUT-OF-FOLD fused probabilities (the 9A fusion strategy "
        "fitted on 4 folds, predicting the 5th), separately for every subset of arms (weights "
        "renormalized over the arms that answer):",
        "",
        "- **Malicious** if P(benign) < t_m, t_m = the largest cut-off whose OOF benign FPR is "
        "≤ 2 % (exactly Part 9A's operating point);",
        "- **Suspicious** if P(benign) < t_s, t_s = the smallest cut-off at which ≥ 95 % of the "
        "OOF threat pages fall below it (never below t_m);",
        "- **Legitimate** otherwise. risk_score = round(100 × (1 − P(benign))). The test pages "
        "were never used for any choice.",
        "",
        "## OOF (train+val, 391 pages - the design targets, not a held-out estimate)",
        "",
    ]
    fired = oof.get("rules_fired", {})
    if fired:
        lines += [
            "Evidence-floor rules firing on the 391 pages (stored Part 3 / Part 8 results; a rule "
            "only CHANGES a verdict when the fusion said Legitimate):",
            "",
            "| rule | benign pages | threat pages |",
            "|---|---|---|",
            *[f"| {rule} | {c['benign']} | {c['threat']} |" for rule, c in fired.items()],
            "",
        ]
    for name, block in oof.items():
        if name == "rules_fired":
            continue
        t = block["thresholds"]
        lines += [
            f"### {name}: arms {t['arms']}",
            "",
            f"Malicious if P(benign) < {t['malicious_below_p_benign']:.4f} (risk ≥ "
            f"{t['malicious_min_risk']}); Suspicious if P(benign) < "
            f"{t['suspicious_below_p_benign']:.4f} (risk ≥ {t['suspicious_min_risk']}).",
            "",
            HEADER,
            _row("(a) fusion tiers", block["fusion_only"]),
            _row("(b) tiers + evidence floor", block["with_floor"]),
            "",
            f"Evidence floor raised {block['floor_raised']['threat_pages']} threat page(s) and "
            f"{block['floor_raised']['benign_pages']} benign page(s) "
            f"{block['floor_raised']['benign_examples'] or ''} "
            f"(n = {block['fusion_only']['n_benign']} benign, "
            f"{block['fusion_only']['n_threat']} threat).",
            "",
        ]
    lines += [
        "## Test (68 pages, live engine in html mode, used once)",
        "",
    ]
    for block in tests:
        name = "with XLM-R (4 arms)" if block["xlmr"] else "without XLM-R (3 arms)"
        lat = block["latency_ms"]
        parity = block["parity"]
        lines += [
            f"### {name}",
            "",
            HEADER,
            _row("(a) fusion tiers", block["fusion_only"]),
            _row("(b) tiers + evidence floor", block["with_floor"]),
            "",
            "- recall per class (b): "
            + ", ".join(
                f"{k} {_pct(v)}" for k, v in block["with_floor"]["recall_per_class"].items()
            ),
            f"- statuses: {block['statuses']}; evidence floor raised "
            f"{block['floor_raised']['threat_pages']} threat / "
            f"{block['floor_raised']['benign_pages']} benign page(s)",
            f"- latency (warm, html mode, CPU): p50 **{lat['p50']} ms**, p95 **{lat['p95']} ms** "
            f"(mean {lat['mean']}, max {lat['max']}); model load {block['load_seconds']} s",
            f"- parity with Part 9A (live vs stored test probabilities): per arm "
            f"{parity['max_abs_diff_per_arm']}, fused {parity['max_abs_diff_fused']}",
            "",
        ]
    lines += [
        "## Reading the numbers (viva)",
        "",
        "- With 34 benign test pages one page = 2.9 % FPR; with 34 threat pages one page = "
        "2.9 % recall. The OOF numbers (193 benign / 198 threat) are tighter.",
        "- The Suspicious band trades benign FPR for recall by design (95 % OOF threat recall): "
        "a Suspicious verdict means 'check before trusting', a Malicious one 'block'.",
        "- The evidence floor only ever raises verdicts; its cost is the benign pages listed "
        "above (rule evidence that also occurs on real sites).",
        "- Parity ≈ 0 shows that the live engine reproduces the stored 9A numbers, i.e. the "
        "API serves the evaluated models.",
    ]
    return "\n".join(lines) + "\n"


def write_report(version: str, oof: dict, tests: list[dict], calibration: dict) -> list[Path]:
    folder = resolve_path(Path("reports")) / "verdict"
    folder.mkdir(parents=True, exist_ok=True)
    md = folder / f"{version}_operating_points.md"
    md.write_text(markdown(version, oof, tests, calibration), encoding="utf-8")
    js = folder / f"{version}_operating_points.json"
    js.write_text(
        json.dumps({"oof": oof, "test": tests, "calibration": calibration}, indent=2),
        encoding="utf-8",
    )
    return [md, js]
