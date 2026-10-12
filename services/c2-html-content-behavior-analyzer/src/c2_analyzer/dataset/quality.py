"""Quality check: flag collected pages that are not the page we wanted.

Part 1: Multilingual dataset preparation (Batch C, Task 11).

Why: by the time a scam URL is fetched it is often dead. The server then
returns a parking page, a "404 Not Found", a hosting "account suspended" page
or a Cloudflare "Just a moment..." challenge, and the file is saved with the
scam label although it contains no scam. Training on such pages teaches the
models that "404 page = phishing". This module finds them with simple,
explainable keyword rules from configs/quality_rules.yaml.

It never deletes anything: it only sets ``quality_flag``. Pages with a flag
other than ok/redirected_offsite are proposed for exclusion in the review
tool, where a person makes the final decision.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

from tqdm import tqdm

from c2_analyzer.config import load_yaml_config
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import PageView, parse_page, read_html


@lru_cache
def quality_rules() -> dict:
    """configs/quality_rules.yaml, read once."""
    return load_yaml_config("quality_rules")


def usable_flags() -> tuple[str, ...]:
    """Flags that still count as good training pages (ok, redirected_offsite)."""
    return tuple(quality_rules()["usable_flags"])


def check_page(view: PageView, html: str, label: str, notes: str | None = None) -> str:
    """Return the quality flag for one page (first matching rule wins, else "ok")."""
    rules = quality_rules()

    empty = rules["empty"]
    if (
        len(view.text) < empty["max_text_chars"]
        and view.element_count <= empty["max_elements"]
        and view.input_count == 0  # a bare login form has little text but is NOT empty
    ):
        return "empty"

    text = view.text.lower()
    raw = html.lower()
    for rule in rules["rules"]:
        if len(view.text) > rule["max_text_chars"]:
            continue
        if "labels" in rule and label not in rule["labels"]:
            continue
        if rule.get("needs_password_field") and not view.has_password_field:
            continue
        if any(phrase in text for phrase in rule.get("phrases", [])) or any(
            pattern in raw for pattern in rule.get("html_patterns", [])
        ):
            return rule["flag"]

    if notes and rules["redirected_offsite_note"] in notes:
        return "redirected_offsite"
    return "ok"


@dataclass
class QualityResult:
    """Outcome of a quality run over the whole dataset."""

    counts: Counter = field(default_factory=Counter)  # flag -> number of samples
    changed: list[tuple[str, str, str]] = field(default_factory=list)  # (id, old, new)
    missing_files: list[str] = field(default_factory=list)  # sample ids


def run_quality(
    store: MetadataStore, dry_run: bool = False, show_progress: bool = False
) -> QualityResult:
    """Set ``quality_flag`` on every sample whose file exists.

    The flag is recomputed each run, so improving a rule in the YAML file
    and running again updates old samples too. With ``dry_run`` the store is
    still updated in memory (so ``dedup`` in the same run can use the flags)
    but nothing is saved.
    """
    result = QualityResult()
    rows = store.df.to_dict("records")
    for row in tqdm(rows, unit="page", disable=not show_progress):
        file = store.raw_dir / row["file_path"]
        if not file.is_file():  # e.g. quarantined by antivirus; validate reports it
            result.missing_files.append(row["sample_id"])
            continue
        html = read_html(file)
        view = parse_page(html, row["final_url"] or row["source_url"])
        flag = check_page(view, html, row["label"], row["notes"] or None)
        result.counts[flag] += 1
        if flag != row["quality_flag"]:
            store.update(row["sample_id"], quality_flag=flag)
            result.changed.append((row["sample_id"], row["quality_flag"], flag))

    if not dry_run and result.changed:
        store.save()
    return result
