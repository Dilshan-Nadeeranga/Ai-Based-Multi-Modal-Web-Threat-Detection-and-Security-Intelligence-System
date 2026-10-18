"""Fairness of the verdict on BENIGN pages by subgroup (Part 9 evaluation; proposal RAI2).

Question: are legitimate Sri Lankan SME / local sites (and Sinhala / Tamil pages) flagged
more often than other legitimate pages? Measured as benign false-positive rate at the two
operating points of the live verdict policy: Suspicious-or-worse ("check first") and
Malicious.

Which predictions:
- OOF (the 391 train+val pages): fused out-of-fold probabilities exactly as the thresholds
  were calibrated (``calibration.fold_models`` / ``oof_for_subset``).
- TEST (68 pages): the saved fusion model on the stored final-arm test probabilities. The
  9B-1 parity check showed the live engine reproduces these to <= 1e-6, so this equals
  running /analyze in html mode (without the time cost).
Both use the serving arms (all fusion arms) and add the evidence floor from the stored
Part 3 / Part 8 results, like ``verdict_eval``.

Subgroup tagging rule (benign pages only, metadata.csv of the frozen version):
- ``lk_sme``   notes match SME / "local company|business|shop|cafe|retail|boutique|
               bookstore|handloom" (the collector's own description of small LK businesses)
- ``lk_other`` not lk_sme, and the registrable domain of source_url or final_url ends in
               ``.lk`` or the notes mention Sri Lanka / "local"
- ``non_lk``   everything else
``lk_all`` = lk_sme + lk_other. Language = metadata language AND the Part 5A detected page
language. Counts are small: Wilson 95 % CIs plus a two-sided Fisher exact test vs non_lk;
a group is FLAGGED when its rate is higher than non_lk's (point estimate) and called
significant only when Fisher p < 0.05.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from c2_analyzer.config import resolve_path
from c2_analyzer.fusion.calibration import fold_models, fuse_arms, oof_for_subset
from c2_analyzer.fusion.verdict import VerdictPolicy, decide
from c2_analyzer.fusion.verdict_eval import page_hits
from c2_analyzer.utils.stats import wilson
from c2_analyzer.utils.url import registrable_domain

SME_RE = re.compile(
    r"\bSME\b|\blocal\s+(?:company|business|shop|cafe|retail|boutique|bookstore|handloom)",
    re.I,
)
LK_NOTE_RE = re.compile(r"sri\s*lanka|\blocal\b", re.I)
FLAGGED = ("Suspicious", "Malicious")


def _domain(url: str) -> str:
    try:
        return registrable_domain(url) or ""
    except Exception:  # noqa: BLE001 - a malformed URL just has no domain
        return ""


def lk_group(notes: str, source_url: str, final_url: str) -> str:
    """The subgroup tag of one benign page (rule in the module docstring)."""
    if SME_RE.search(notes or ""):
        return "lk_sme"
    domains = {_domain(source_url or ""), _domain(final_url or "")}
    if any(d.endswith(".lk") for d in domains if d) or LK_NOTE_RE.search(notes or ""):
        return "lk_other"
    return "non_lk"


def page_table(version: str) -> pd.DataFrame:
    """One row per manifest page: label + subgroup tags (metadata) + detected language."""
    root = resolve_path(Path("data/metadata"))
    manifest = pd.read_csv(root / "manifests" / f"dataset_{version}.csv", dtype=str)
    meta = pd.read_csv(root / "metadata.csv", dtype=str).fillna("")
    meta = meta[meta.sample_id.isin(manifest.sample_id)].set_index("sample_id")
    text_index = resolve_path(Path("data/processed/text") / version / "text_index.csv")
    detected = (
        pd.read_csv(text_index, dtype=str).set_index("sample_id")["page_language"]
        if text_index.is_file()
        else pd.Series(dtype=str)
    )
    rows = []
    for sample_id, r in meta.iterrows():
        rows.append(
            {
                "sample_id": sample_id,
                "label": r["label"],
                "source": r["source"],
                "metadata_language": r["language"] or "unknown",
                "detected_language": detected.get(sample_id, "unknown"),
                "lk_group": lk_group(r["notes"], r["source_url"], r["final_url"]),
            }
        )
    return pd.DataFrame(rows).set_index("sample_id")


def benign_verdicts(version: str) -> pd.DataFrame:
    """Verdict (fusion + evidence floor) of every BENIGN pool / test page."""
    from c2_analyzer.fusion.common import FusionConfig
    from c2_analyzer.fusion.data import FusionData
    from c2_analyzer.fusion.model import load_bundle, restore

    config = FusionConfig.load()
    policy = VerdictPolicy.load()
    bundle = load_bundle(config.models_dir(version))
    if bundle is None:
        raise FileNotFoundError(f"no fusion model for {version} - run run_ablation.py first")
    data = FusionData.load(version, config)
    arms = list(policy.calibration["fusion_arms"])
    thresholds = policy.for_arms(arms)
    labels = data.labels

    models, inputs = fold_models(data, bundle, config)
    pool_ids = data.ids("pool")
    parts = {
        "oof": (pool_ids, data.y("pool"), oof_for_subset(models, inputs, data.folds(), arms)),
    }
    test_ids = data.ids("test")
    parts["test"] = (
        test_ids,
        data.y("test"),
        fuse_arms(restore(bundle), data.inputs(arms, test_ids), arms),
    )
    rows = []
    for part, (ids, y, proba) in parts.items():
        for sample_id, label, p in zip(ids, y, proba, strict=True):
            if labels[int(label)] != "benign":
                continue
            probs = {c: float(v) for c, v in zip(labels, p, strict=True)}
            decision = decide(probs, thresholds, page_hits(policy, version, sample_id))
            rows.append(
                {
                    "sample_id": sample_id,
                    "part": part,
                    "verdict": decision.verdict,
                    "p_benign": probs["benign"],
                }
            )
    out = pd.DataFrame(rows).set_index("sample_id")
    out.attrs["arms"] = arms
    out.attrs["thresholds"] = thresholds.as_dict()
    return out


def _fisher(k1: int, n1: int, k2: int, n2: int) -> float | None:
    if not n1 or not n2:
        return None
    from scipy.stats import fisher_exact

    return float(fisher_exact([[k1, n1 - k1], [k2, n2 - k2]])[1])


def group_rates(frame: pd.DataFrame, column: str, reference: str | None) -> list[dict]:
    """Benign FPR per value of ``column`` (Suspicious-or-worse and Malicious)."""
    out = []
    ref = frame[frame[column] == reference] if reference else None
    for value, g in sorted(frame.groupby(column), key=lambda kv: -len(kv[1])):
        row = {"group": value, "n": len(g)}
        for key, verdicts in (("flagged", FLAGGED), ("malicious", ("Malicious",))):
            k = int(g.verdict.isin(verdicts).sum())
            rate = wilson(k, len(g))
            row[key] = rate.as_dict() | {"text": rate.text()}
            if ref is not None and value != reference:
                k_ref = int(ref.verdict.isin(verdicts).sum())
                row[key]["fisher_p_vs_reference"] = _fisher(k, len(g), k_ref, len(ref))
                row[key]["higher_than_reference"] = bool(
                    len(ref) and len(g) and k / len(g) > k_ref / len(ref)
                )
        row["examples_flagged"] = g[g.verdict.isin(FLAGGED)].index.tolist()[:8]
        out.append(row)
    return out


def evaluate(version: str) -> dict:
    pages = page_table(version)
    verdicts = benign_verdicts(version)
    frame = verdicts.join(pages, how="left")
    frame["lk_all"] = np.where(frame.lk_group == "non_lk", "non_lk", "lk_all")
    result = {
        "version": version,
        "arms": verdicts.attrs["arms"],
        "thresholds": verdicts.attrs["thresholds"],
        "tagging_rule": __doc__.split("Subgroup tagging rule")[1].split("Counts are small")[0],
        "scopes": {},
    }
    for scope, part in (("OOF + test", None), ("OOF", "oof"), ("test", "test")):
        f = frame if part is None else frame[frame.part == part]
        result["scopes"][scope] = {
            "n_benign": len(f),
            "lk_group": group_rates(f, "lk_group", "non_lk"),
            "lk_all": group_rates(f, "lk_all", "non_lk"),
            "metadata_language": group_rates(f, "metadata_language", "en"),
            "detected_language": group_rates(f, "detected_language", "en"),
            "source": group_rates(f, "source", None),
        }
    result["flags"] = _flags(result["scopes"]["OOF + test"])
    return result


def _flags(scope: dict) -> list[str]:
    flags = []
    for table in ("lk_group", "lk_all", "metadata_language", "detected_language"):
        for row in scope[table]:
            for key, name in (("flagged", "Suspicious-or-worse"), ("malicious", "Malicious")):
                cell = row[key]
                if cell.get("higher_than_reference"):
                    p = cell.get("fisher_p_vs_reference")
                    sig = "significant" if p is not None and p < 0.05 else "not significant"
                    flags.append(
                        f"{table}={row['group']}: {name} FPR {cell['text']} is higher than the "
                        f"reference (Fisher p = {p:.3f}, {sig}; n = {row['n']})"
                    )
    return flags


def _table(rows: list[dict], reference: str | None) -> list[str]:
    head = "| group | n | Suspicious-or-worse FPR [95 % CI] | Malicious FPR [95 % CI] |"
    lines = [head + (" Fisher p (S+ / M) |" if reference else ""), "|---|---|---|---|"]
    lines[1] += "---|" if reference else ""
    for r in rows:
        line = f"| {r['group']} | {r['n']} | {r['flagged']['text']} | {r['malicious']['text']} |"
        if reference:
            ps = [r[k].get("fisher_p_vs_reference") for k in ("flagged", "malicious")]
            line += (
                " ref |"
                if r["group"] == reference
                else " " + " / ".join("—" if p is None else f"{p:.3f}" for p in ps) + " |"
            )
        lines.append(line)
    return lines


def markdown(result: dict) -> str:
    t = result["thresholds"]
    lines = [
        f"# Fairness of the verdict on benign pages - {result['version']}",
        "",
        "Benign false-positive rate per subgroup at the live operating points "
        f"(arms: {', '.join(result['arms'])}; thresholds {t}). Suspicious-or-worse = the "
        "'check first' band, Malicious = the ≤ 2 % OOF FPR cut-off; the evidence floor is "
        "applied. OOF = 391 train+val pages (where the thresholds were fitted - design "
        "numbers); test = 68 held-out pages. Wilson 95 % CIs; Fisher exact test vs the "
        "reference group. **Small n: one page moves a small group's rate by 10-25 points.**",
        "",
        "## Tagging rule",
        "",
        "```text" + result["tagging_rule"].rstrip() + "\n```",
        "",
        "## Flags (OOF + test)",
        "",
    ]
    lk_flags = [f for f in result["flags"] if f.startswith(("lk_group=", "lk_all="))]
    lines.append(
        "- **Sri Lankan SME / local sites: "
        + (
            "FLAGGED MORE than other benign pages"
            if lk_flags
            else "NOT flagged more than other " "benign pages"
        )
        + "** at either operating point (tables below)."
    )
    lines += [f"- {f}" for f in result["flags"]]
    for scope, s in result["scopes"].items():
        lines += ["", f"## {scope} ({s['n_benign']} benign pages)", ""]
        for key, title, ref in (
            ("lk_group", "Sri Lankan SME / local vs other", "non_lk"),
            ("lk_all", "All Sri Lankan vs other", "non_lk"),
            ("metadata_language", "Metadata language", "en"),
            ("detected_language", "Detected page language (Part 5A)", "en"),
            ("source", "Collection source", None),
        ):
            lines += [f"### {title}", ""] + _table(s[key], ref) + [""]
            flagged = [
                f"`{r['group']}`: " + ", ".join(f"`{x}`" for x in r["examples_flagged"])
                for r in s[key]
                if r["examples_flagged"] and key in ("lk_group", "detected_language")
            ]
            if flagged and scope == "OOF + test":
                lines += ["Flagged pages: " + "; ".join(flagged), ""]
    return "\n".join(lines) + "\n"
