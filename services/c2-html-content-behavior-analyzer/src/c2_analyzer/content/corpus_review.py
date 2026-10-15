"""Manual verification of the scam-text corpus: review session + peer agreement.

Part 5: Multilingual scam content analyzer (Batch B, Task 14).

Why: page segments are only WEAK-labelled by cue words, and even my own given
labels for real messages deserve a second look. A person must confirm,
correct or exclude each text before it is trusted in validation / test.
This module holds the logic; the terminal UI is scripts/review_corpus.py
(same style as Part 1's review_labels.py).

- Every decision is saved at once to data/corpus/review/corpus_reviews.csv
  (``corpus.ReviewStore``), so a review can stop at any key press and resume.
  A rebuild of the corpus re-applies the decisions (text_ids are stable).
- Confirming a text also pins its current intents and language, so a later
  change of the cue words can never silently change a verified label.
- Texts are shown as plain text only, with control / bidi characters
  stripped (Part 1 ``terminal_safe``).

Peer check (for the report): a second person labels a random share of my
verified texts WITHOUT seeing my labels; agreement % and Cohen's kappa
(Part 1 ``verifier.agreement``) are reported overall and per language.
"""

from __future__ import annotations

import json
import random
import textwrap
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from c2_analyzer.content.corpus import ReviewStore, active_rows, corpus_rules
from c2_analyzer.content.taxonomy import BENIGN, Taxonomy, load_taxonomy
from c2_analyzer.dataset.page_view import terminal_safe
from c2_analyzer.dataset.verifier import agreement, describe_kappa

REVIEW_LANGUAGES = ("en", "si", "ta", "si_latn", "ta_latn", "mixed", "other")
PEER_COLUMNS = ["text_id", "language", "text", "peer_primary_intent", "peer_intents"]
KEYS = "[c]onfirm  change [i]ntents  [l]anguage  e[x]clude  [s]kip  [b]ack  [q]uit"


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def exclusion_reasons() -> tuple[str, ...]:
    return tuple(corpus_rules()["exclusion_reasons"])


def select_rows(
    frame: pd.DataFrame,
    language: str | None = None,
    source_type: str | None = None,
    intent: str | None = None,
    split: str | None = None,
    only_unverified: bool = True,
    needs_review: bool = False,
    random_order: bool = False,
    seed: int | None = None,
    limit: int | None = None,
) -> list[str]:
    """text_ids to review, in corpus order (or shuffled with a seed)."""
    mask = pd.Series(True, index=frame.index)
    if language:
        mask &= frame["language"] == language
    if source_type:
        mask &= frame["source_type"] == source_type
    if intent:
        mask &= frame["intents"].str.split(";").apply(lambda names: intent in names)
    if split:
        mask &= frame["split"] == split
    if only_unverified:
        mask &= (frame["verified"] != "true") & (frame["excluded"] != "true")
    if needs_review:
        mask &= frame["needs_review"] == "true"
    ids = frame.loc[mask, "text_id"].tolist()
    if random_order:
        random.Random(seed).shuffle(ids)
    return ids[:limit] if limit is not None else ids


def describe_row(row: dict[str, str]) -> str:
    """One corpus row as plain text for the terminal."""
    status = "VERIFIED" if row["verified"] == "true" else "unverified"
    if row["excluded"] == "true":
        status = f"EXCLUDED ({row['exclusion_reason']})"
    origin = row["source_type"]
    if row["field"]:
        origin += f" / {row['field']}"
    if row["page_label"]:
        origin += f" / page label: {row['page_label']}"
    language = row["language"]
    if row["language_given"] and row["language_given"] != row["language"]:
        language += f"  (given: {row['language_given']})"
    lines = [
        f"{row['text_id']}   split {row['split']}   {status}"
        + ("   NEEDS REVIEW" if row["needs_review"] == "true" else ""),
        f"language:  {language}",
        f"source:    {origin}   ref {row['source_ref']}",
        f"intents:   {row['intents'].replace(';', ', ')}   (from {row['intent_source']}; "
        f"cue words suggest: {row['cue_intents'].replace(';', ', ') or '-'})",
    ]
    if row["notes"]:
        lines.append(f"notes:     {terminal_safe(row['notes'])}")
    lines += [
        "",
        textwrap.fill(
            terminal_safe(row["text"]), 100, initial_indent="    ", subsequent_indent="    "
        ),
    ]
    return "\n".join(lines)


def parse_intent_choice(answer: str, taxonomy: Taxonomy) -> list[str] | None:
    """'3 1' -> [3rd intent, 1st intent] (first = primary); None if invalid."""
    ids = taxonomy.ids
    numbers = answer.replace(",", " ").split()
    if not numbers or not all(n.isdigit() and 1 <= int(n) <= len(ids) for n in numbers):
        return None
    chosen = list(dict.fromkeys(ids[int(n) - 1] for n in numbers))
    if BENIGN in chosen and len(chosen) > 1:
        return None  # benign means "no other intent"
    return chosen


@dataclass
class CorpusReviewSession:
    """Shows corpus rows one by one and saves each decision immediately.

    ``ask`` and ``show`` default to input / print; tests replace them.
    """

    frame: pd.DataFrame  # the corpus with reviews applied (updated in place for display)
    store: ReviewStore
    reviewer: str
    text_ids: list[str]
    ask: Callable[[str], str] = input
    show: Callable[[str], None] = print
    taxonomy: Taxonomy = field(default_factory=load_taxonomy)
    decisions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._index = {
            text_id: i for i, text_id in zip(self.frame.index, self.frame["text_id"], strict=True)
        }

    def row(self, text_id: str) -> dict[str, str]:
        return self.frame.loc[self._index[text_id]].to_dict()

    def _set(self, text_id: str, **values: str) -> None:
        for key, value in values.items():
            self.frame.at[self._index[text_id], key] = value

    def reviewed_count(self) -> int:
        rows = self.frame[self.frame["text_id"].isin(self.text_ids)]
        return int(((rows["verified"] == "true") | (rows["excluded"] == "true")).sum())

    def choose(self, title: str, options: tuple[str, ...]) -> str | None:
        self.show(title)
        for number, option in enumerate(options, start=1):
            self.show(f"  {number}. {option}")
        answer = self.ask("number (Enter = cancel): ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        if answer:
            self.show("Not a valid number - cancelled.")
        return None

    # ---- the actions (each one saves) ----------------------------------------------------

    def confirm(self, text_id: str) -> None:
        row = self.row(text_id)
        values = dict(
            intents=row["intents"],
            primary_intent=row["primary_intent"],
            language=row["language"],
            verified="true",
            verified_by=self.reviewer,
            verified_at=now(),
            excluded="false",
            exclusion_reason="",
        )
        self.store.save_decision(text_id, **values)
        self._set(text_id, needs_review="false", **values)

    def change_intents(self, text_id: str, intents: list[str]) -> None:
        values = dict(
            intents=";".join(intents),
            primary_intent=intents[0],
            language=self.row(text_id)["language"],
            verified="true",
            verified_by=self.reviewer,
            verified_at=now(),
            excluded="false",
            exclusion_reason="",
        )
        self.store.save_decision(text_id, **values)
        self._set(text_id, intent_source="reviewer", needs_review="false", **values)

    def set_language(self, text_id: str, language: str) -> None:
        self.store.save_decision(text_id, language=language)
        self._set(text_id, language=language)

    def exclude(self, text_id: str, reason: str) -> None:
        values = dict(
            excluded="true",
            exclusion_reason=reason,
            verified="false",
            verified_by=self.reviewer,
            verified_at=now(),
        )
        self.store.save_decision(text_id, **values)
        self._set(text_id, needs_review="false", **values)

    # ---- the loop ---------------------------------------------------------------------------

    def ask_intents(self) -> list[str] | None:
        self.show("Intents (numbers separated by spaces, first = primary):")
        for number, intent_id in enumerate(self.taxonomy.ids, start=1):
            self.show(f"  {number}. {intent_id}")
        answer = self.ask("numbers (Enter = cancel): ").strip()
        if not answer:
            return None
        chosen = parse_intent_choice(answer, self.taxonomy)
        if chosen is None:
            self.show("Invalid choice (benign cannot be combined) - cancelled.")
        return chosen

    def run(self) -> dict[str, str]:
        if not self.text_ids:
            self.show("Nothing to review with these filters.")
            return self.decisions
        index = 0
        while 0 <= index < len(self.text_ids):
            text_id = self.text_ids[index]
            total = len(self.text_ids)
            self.show("\n" + "=" * 100)
            self.show(f"[{index + 1}/{total}]   {self.reviewed_count()}/{total} reviewed")
            self.show(describe_row(self.row(text_id)))
            self.show(KEYS)
            key = self.ask("> ").strip().lower()
            if key == "q":
                break
            if key == "b":
                index = max(index - 1, 0)
            elif key == "s":
                index += 1
            elif key == "c":
                self.confirm(text_id)
                self.decisions[text_id] = "confirmed"
                index += 1
            elif key == "i":
                intents = self.ask_intents()
                if intents:
                    self.change_intents(text_id, intents)
                    self.decisions[text_id] = "intents " + ";".join(intents)
                    index += 1
            elif key == "l":  # fixes the language, then shows the same row again
                language = self.choose("Language:", REVIEW_LANGUAGES)
                if language:
                    self.set_language(text_id, language)
            elif key == "x":
                reason = self.choose("Exclusion reason:", exclusion_reasons())
                if reason:
                    self.exclude(text_id, reason)
                    self.decisions[text_id] = f"excluded ({reason})"
                    index += 1
            else:
                self.show(f"Unknown key {key!r}. Keys: {KEYS}")
        self.show(f"\nSaved. {self.reviewed_count()}/{len(self.text_ids)} reviewed.")
        return self.decisions


# ---- peer agreement ------------------------------------------------------------------------


def export_peer_sheet(
    frame: pd.DataFrame, out_path: Path, fraction: float = 0.1, seed: int = 42
) -> pd.DataFrame:
    """A random ``fraction`` of my verified texts PER LANGUAGE, without my labels.

    Sampling per language (at least one text each) makes a per-language kappa
    possible even though English dominates. UTF-8 with BOM so Excel shows
    Sinhala / Tamil correctly.
    """
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be between 0 and 1")
    pool = active_rows(frame)
    pool = pool[pool["verified"] == "true"]
    if pool.empty:
        raise ValueError("No verified texts yet - review some with scripts/review_corpus.py.")
    parts = [
        group.sample(n=max(1, round(len(group) * fraction)), random_state=seed)
        for _, group in pool.groupby("language", sort=True)
    ]
    chosen = pd.concat(parts).sample(frac=1, random_state=seed)  # mixed order for the peer
    sheet = chosen[["text_id", "language", "text"]].assign(peer_primary_intent="", peer_intents="")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sheet.to_csv(out_path, index=False, columns=PEER_COLUMNS, encoding="utf-8-sig")
    return sheet


def _agreement_block(mine: list[str], peer: list[str]) -> dict[str, Any]:
    percent, kappa = agreement(mine, peer)
    return {
        "rated": len(mine),
        "agreement_percent": round(percent, 2),
        "cohen_kappa": None if kappa is None else round(kappa, 4),
        "kappa_interpretation": describe_kappa(kappa),
    }


def import_peer_sheet(frame: pd.DataFrame, sheet_path: Path, out_path: Path) -> dict[str, Any]:
    """Compare the peer's primary intents with mine -> corpus_peer_agreement.json (ids only)."""
    sheet = pd.read_csv(sheet_path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    missing = {"text_id", "peer_primary_intent"} - set(sheet.columns)
    if missing:
        raise ValueError(f"{sheet_path} is missing column(s) {sorted(missing)}")
    sheet["peer_primary_intent"] = sheet["peer_primary_intent"].str.strip().str.lower()
    rated = sheet[sheet["peer_primary_intent"] != ""]
    if rated.empty:
        raise ValueError("No peer_primary_intent filled in yet.")
    taxonomy = load_taxonomy()
    unknown = sorted(set(rated["peer_primary_intent"]) - set(taxonomy.ids))
    if unknown:
        raise ValueError(f"unknown intent(s) {unknown}; allowed: {', '.join(taxonomy.ids)}")
    corpus = frame.set_index("text_id")
    not_found = sorted(set(rated["text_id"]) - set(corpus.index))
    if not_found:
        raise KeyError(f"text_id(s) not in the corpus: {not_found[:5]}")

    mine = [corpus.at[text_id, "primary_intent"] for text_id in rated["text_id"]]
    languages = [corpus.at[text_id, "language"] for text_id in rated["text_id"]]
    peer = rated["peer_primary_intent"].tolist()
    per_language = {}
    for language in sorted(set(languages)):
        picks = [i for i, lang in enumerate(languages) if lang == language]
        per_language[language] = _agreement_block(
            [mine[i] for i in picks], [peer[i] for i in picks]
        )
    report = {
        **_agreement_block(mine, peer),
        "unrated_rows": len(sheet) - len(rated),
        "per_language": per_language,
        "intents": taxonomy.ids,
        "disagreements": [
            {"text_id": text_id, "language": lang, "my_intent": a, "peer_intent": b}
            for text_id, lang, a, b in zip(rated["text_id"], languages, mine, peer, strict=True)
            if a != b
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
