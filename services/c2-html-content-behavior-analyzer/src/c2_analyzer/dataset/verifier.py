"""Manual label verification: review actions, the review session and peer agreement.

Part 1: Multilingual dataset preparation (Batch C, Task 12).

Why: feed labels are only suggestions. An OpenPhish URL may already show a
parking page, a "crypto_scam" may really be a fake shop. A person has to look
at every sample once and confirm, correct or exclude it - otherwise the
models learn from wrong labels. This module holds the logic; the terminal UI
is scripts/review_labels.py.

Safety: a sample is only ever shown as TEXT (title, visible text, form
summary). The page is never opened in a browser and control characters are
stripped before printing (see page_view.terminal_safe).

Decisions are written straight to metadata.csv after every key press, so a
review can be stopped at any time and resumed later.

Peer verification (for the report): a second person labels a random 10%
without seeing my labels; Cohen's kappa measures how much we agree beyond
chance (1 = perfect, 0 = no better than guessing).
"""

from __future__ import annotations

import json
import os
import random
import textwrap
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import pandas as pd

from c2_analyzer.config import get_labels, get_languages
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import PageView, load_page, terminal_safe
from c2_analyzer.dataset.quality import quality_rules

TEXT_PREVIEW_CHARS = 600
PEER_EXCERPT_CHARS = 300
PEER_COLUMNS = ["sample_id", "title", "text_excerpt", "form_summary", "peer_label"]


def exclusion_reasons() -> tuple[str, ...]:
    return tuple(quality_rules()["exclusion_reasons"])


# ---- review actions (each one validates and saves) -------------------------------------


def confirm_sample(store: MetadataStore, sample_id: str, reviewer: str) -> None:
    """The label is right: mark verified (and undo an earlier exclusion)."""
    store.update(
        sample_id,
        verified=True,
        verified_by=reviewer,
        verification_date=date.today(),
        excluded=False,
        exclusion_reason=None,
    )
    store.save()


def relabel_sample(store: MetadataStore, sample_id: str, new_label: str, reviewer: str) -> None:
    """Correct the label: move the file to the new label folder and mark verified.

    The sample_id never changes (see schemas/dataset.py); the first label is
    kept in ``label_original``. If anything fails, the file is moved back
    and metadata.csv is left as it was.
    """
    record = store.get(sample_id)
    if new_label == record.label:
        confirm_sample(store, sample_id, reviewer)
        return
    if new_label not in get_labels():
        raise ValueError(f"unknown label {new_label!r}")

    old_file = store.raw_dir / record.file_path
    file_name = Path(record.file_path).name
    new_file = store.raw_dir / new_label / file_name
    if new_file.exists():
        raise FileExistsError(f"{new_file} already exists")
    original = record.label_original or record.label

    new_file.parent.mkdir(parents=True, exist_ok=True)
    os.replace(old_file, new_file)  # a move on the same disk
    try:
        store.update(
            sample_id,
            label=new_label,
            file_path=f"{new_label}/{file_name}",
            label_original=None if new_label == original else original,
            verified=True,
            verified_by=reviewer,
            verification_date=date.today(),
            excluded=False,
            exclusion_reason=None,
        )
        store.save()
    except BaseException:
        os.replace(new_file, old_file)
        store.load()  # throw away the in-memory change
        raise


def set_language(store: MetadataStore, sample_id: str, language: str) -> None:
    store.update(sample_id, language=language)
    store.save()


def exclude_sample(store: MetadataStore, sample_id: str, reason: str) -> None:
    """Keep the file but never use it for training."""
    store.update(sample_id, excluded=True, exclusion_reason=reason)
    store.save()


# ---- choosing what to review ---------------------------------------------------------


def select_samples(
    store: MetadataStore,
    label: str | None = None,
    language: str | None = None,
    only_unverified: bool = True,
    only_flagged: bool = False,
    representatives_only: bool = False,
    random_order: bool = False,
    limit: int | None = None,
    seed: int | None = None,
) -> list[str]:
    """Sample ids to review, in order.

    only_unverified: skip samples already verified or excluded.
    only_flagged: only pages whose quality_flag is not "ok".
    representatives_only: skip pages marked as a near-duplicate of another.
    """
    df = store.df
    mask = pd.Series(True, index=df.index)
    if label:
        mask &= df["label"] == label
    if language:
        mask &= df["language"] == language
    if only_unverified:
        mask &= (df["verified"] != "true") & (df["excluded"] != "true")
    if only_flagged:
        mask &= df["quality_flag"] != "ok"
    if representatives_only:
        mask &= df["is_duplicate_of"] == ""
    ids = df.loc[mask, "sample_id"].tolist()
    if random_order:
        random.Random(seed).shuffle(ids)
    return ids[:limit] if limit is not None else ids


# ---- showing a sample as text ----------------------------------------------------------


def page_for(store: MetadataStore, sample_id: str) -> PageView | None:
    row = store.get(sample_id)
    file = store.raw_dir / row.file_path
    if not file.is_file():
        return None
    return load_page(file, row.final_url or row.source_url)


def cluster_info(store: MetadataStore, sample_id: str) -> str:
    row = store.get(sample_id)
    if not row.cluster_id:
        return "not clustered yet (run deduplicate.py dedup)"
    size = int((store.df["cluster_id"] == row.cluster_id).sum())
    if size == 1:
        return f"{row.cluster_id} (no near-duplicates)"
    role = f"duplicate of {row.is_duplicate_of}" if row.is_duplicate_of else "representative"
    return f"{row.cluster_id} ({size} pages, this one is the {role})"


def describe_sample(store: MetadataStore, sample_id: str) -> str:
    """Everything the reviewer needs, as plain text safe for a terminal."""
    row = store.get(sample_id)
    proposal = ""
    if row.quality_flag not in quality_rules()["usable_flags"]:
        proposal = "   <- proposed: exclude"
    lines = [
        f"sample_id : {row.sample_id}",
        f"label     : {row.label}"
        + (f"   (originally {row.label_original})" if row.label_original else ""),
        f"language  : {row.language}",
        f"source    : {row.source}",
        f"source_url: {row.source_url}",
        f"final_url : {row.final_url or '-'}",
        f"quality   : {row.quality_flag}{proposal}",
        f"cluster   : {cluster_info(store, sample_id)}",
        f"notes     : {row.notes or '-'}",
    ]
    if row.verified:
        lines.append(f"verified  : yes, by {row.verified_by} on {row.verification_date}")
    if row.excluded:
        lines.append(f"EXCLUDED  : {row.exclusion_reason}")

    view = page_for(store, sample_id)
    if view is None:
        lines.append("\n(file not found - quarantined by antivirus?)")
        return terminal_safe("\n".join(lines))
    lines.append("")
    lines.append(f"title     : {view.title or '-'}")
    lines.append(f"text ({len(view.text)} chars):")
    preview = view.text[:TEXT_PREVIEW_CHARS] + (
        "..." if len(view.text) > TEXT_PREVIEW_CHARS else ""
    )
    lines.extend("  " + line for line in textwrap.wrap(preview or "(no visible text)", 96))
    lines.append(f"forms     : {len(view.forms)}")
    lines.extend(f"  - {form.summary()}" for form in view.forms)
    lines.append(f"scripts   : {view.script_count}    iframes: {view.iframe_count}")
    top = ", ".join(f"{domain} ({count})" for domain, count in view.external_domains.most_common(5))
    lines.append(f"external  : {top or '-'}")
    return terminal_safe("\n".join(lines))


# ---- the interactive session -----------------------------------------------------------

KEYS = "[c]onfirm  [r]elabel  [l]anguage  e[x]clude  [s]kip  [b]ack  [q]uit"


@dataclass
class ReviewSession:
    """Shows samples one by one and applies the reviewer's decisions.

    ``ask`` and ``show`` default to input/print; tests replace them.
    """

    store: MetadataStore
    reviewer: str
    sample_ids: list[str]
    ask: Callable[[str], str] = input
    show: Callable[[str], None] = print
    decisions: dict[str, str] = field(default_factory=dict)  # sample_id -> what was done

    def reviewed_count(self) -> int:
        df = self.store.df
        done = df[df["sample_id"].isin(self.sample_ids)]
        return int(((done["verified"] == "true") | (done["excluded"] == "true")).sum())

    def choose(self, title: str, options: tuple[str, ...]) -> str | None:
        """Numbered menu; returns the chosen option or None (empty answer = cancel)."""
        self.show(title)
        for number, option in enumerate(options, start=1):
            self.show(f"  {number}. {option}")
        answer = self.ask("number (Enter = cancel): ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        if answer:
            self.show("Not a valid number - cancelled.")
        return None

    def run(self) -> dict[str, str]:
        """Review loop. Returns the decisions made in this session."""
        if not self.sample_ids:
            self.show("Nothing to review with these filters.")
            return self.decisions
        index = 0
        while 0 <= index < len(self.sample_ids):
            sample_id = self.sample_ids[index]
            total = len(self.sample_ids)
            self.show("\n" + "=" * 100)
            self.show(f"[{index + 1}/{total}]   {self.reviewed_count()}/{total} reviewed")
            self.show(describe_sample(self.store, sample_id))
            self.show(KEYS)
            key = self.ask("> ").strip().lower()

            if key == "q":
                break
            if key == "b":
                index = max(index - 1, 0)
                continue
            if key == "s":
                index += 1
                continue
            if key == "c":
                confirm_sample(self.store, sample_id, self.reviewer)
                self.decisions[sample_id] = "confirmed"
                index += 1
            elif key == "r":
                label = self.choose("New label:", get_labels())
                if label:
                    relabel_sample(self.store, sample_id, label, self.reviewer)
                    self.decisions[sample_id] = f"relabelled to {label}"
                    index += 1
            elif key == "l":  # fixes the language, then shows the same sample again
                language = self.choose("Language:", get_languages())
                if language:
                    set_language(self.store, sample_id, language)
            elif key == "x":
                reason = self.choose("Exclusion reason:", exclusion_reasons())
                if reason:
                    exclude_sample(self.store, sample_id, reason)
                    self.decisions[sample_id] = f"excluded ({reason})"
                    index += 1
            else:
                self.show(f"Unknown key {key!r}. Keys: {KEYS}")

        self.show(f"\nSaved. {self.reviewed_count()}/{len(self.sample_ids)} reviewed.")
        return self.decisions


# ---- peer verification -----------------------------------------------------------------


def export_peer_sheet(
    store: MetadataStore, out_path: Path, fraction: float = 0.1, seed: int = 42
) -> pd.DataFrame:
    """Write a random ``fraction`` of my verified, non-excluded samples for a second rater.

    The sheet shows only what the peer needs to judge the page - NO label,
    source or URL (a URL from "openphish" would give the answer away).
    UTF-8 with BOM, so Excel shows Sinhala/Tamil text correctly.
    """
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be between 0 and 1")
    df = store.df
    pool = df[(df["verified"] == "true") & (df["excluded"] != "true")]
    if pool.empty:
        raise ValueError("No verified samples yet - review some samples first.")
    count = max(1, round(len(pool) * fraction))
    chosen = pool.sample(n=count, random_state=seed)["sample_id"]

    rows = []
    for sample_id in chosen:
        view = page_for(store, sample_id)
        rows.append(
            {
                "sample_id": sample_id,
                "title": view.title if view else "",
                "text_excerpt": view.text[:PEER_EXCERPT_CHARS] if view else "(file missing)",
                "form_summary": "; ".join(form.summary() for form in view.forms) if view else "",
                "peer_label": "",
            }
        )
    sheet = pd.DataFrame(rows, columns=PEER_COLUMNS)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sheet.to_csv(out_path, index=False, encoding="utf-8-sig")
    return sheet


KAPPA_SCALE = [  # Landis & Koch (1977), the usual way to describe kappa; below 0 = "poor"
    (0.20, "slight"),
    (0.40, "fair"),
    (0.60, "moderate"),
    (0.80, "substantial"),
    (1.01, "almost perfect"),
]


def describe_kappa(kappa: float | None) -> str:
    if kappa is None:
        return "undefined"
    if kappa < 0:
        return "poor"
    return next(name for limit, name in KAPPA_SCALE if kappa <= limit)


def agreement(mine: list[str], peer: list[str]) -> tuple[float, float | None]:
    """(percent agreement, Cohen's kappa). Kappa is None when it is undefined.

    kappa = (p_observed - p_chance) / (1 - p_chance). It is undefined when
    both raters used one and the same label for everything (p_chance = 1).
    """
    from sklearn.metrics import cohen_kappa_score  # heavy import, only needed here

    percent = 100 * sum(a == b for a, b in zip(mine, peer, strict=True)) / len(mine)
    if len(set(mine) | set(peer)) == 1:
        return percent, None
    return percent, float(cohen_kappa_score(mine, peer))


@dataclass
class PeerResult:
    rated: int
    agreement_percent: float
    cohen_kappa: float | None
    disagreements: list[dict]
    unrated: int


def import_peer_sheet(store: MetadataStore, sheet_path: Path, out_path: Path) -> PeerResult:
    """Compare the peer's labels with mine and write peer_agreement.json."""
    sheet = pd.read_csv(sheet_path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    missing = {"sample_id", "peer_label"} - set(sheet.columns)
    if missing:
        raise ValueError(f"{sheet_path} is missing column(s) {sorted(missing)}")

    sheet["peer_label"] = sheet["peer_label"].str.strip().str.lower()
    rated = sheet[sheet["peer_label"] != ""]
    if rated.empty:
        raise ValueError("No peer_label filled in yet.")
    unknown = sorted(set(rated["peer_label"]) - set(get_labels()))
    if unknown:
        raise ValueError(
            f"unknown peer_label value(s) {unknown}; allowed: {', '.join(get_labels())}"
        )

    mine = [store.get(sample_id).label for sample_id in rated["sample_id"]]  # KeyError if unknown
    peer = rated["peer_label"].tolist()
    percent, kappa = agreement(mine, peer)
    disagreements = [
        {"sample_id": sample_id, "my_label": a, "peer_label": b}
        for sample_id, a, b in zip(rated["sample_id"], mine, peer, strict=True)
        if a != b
    ]
    result = PeerResult(len(rated), percent, kappa, disagreements, len(sheet) - len(rated))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "rated_samples": result.rated,
        "unrated_rows": result.unrated,
        "agreement_percent": round(percent, 2),
        "cohen_kappa": None if kappa is None else round(kappa, 4),
        "kappa_interpretation": describe_kappa(kappa),
        "labels": list(get_labels()),
        "disagreements": disagreements,
    }
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return result
