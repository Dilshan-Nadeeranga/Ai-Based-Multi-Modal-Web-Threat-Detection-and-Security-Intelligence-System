"""Part 3 pipeline: ParsedPage (+ raw HTML) -> DomResult (feature vector + evidence).

Part 3: DOM structural analysis.

Core principle: Part 3 turns Part 2's ParsedPage into a FIXED-ORDER NUMERIC
FEATURE VECTOR plus human-readable EVIDENCE.
- Input is a ParsedPage (stored JSON or produced on the fly). The raw HTML is
  parsed again ONLY for tree metrics Part 2 does not store (average depth,
  leaf ratio, hidden elements), with Part 2's own parser and visibility
  helpers - Part 2's logic is reused, never duplicated.
- No machine learning here (Part 4) and no JavaScript semantics (Part 7):
  scripts are only counted.
- The same ``extract_dom_features(page, html=None)`` serves dataset samples
  (batch.py) and the API (Part 9).

Feature groups run isolated, like Part 2's steps: if one group fails, its
features are 0, the error is recorded in ``errors`` and the vector is still
complete (every feature present, finite, in dictionary order).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from c2_analyzer.dom import tree as dom_tree
from c2_analyzer.dom.dictionary import dictionary_hash, load_dictionary, specs
from c2_analyzer.dom.element_features import element_features
from c2_analyzer.dom.evidence import build_evidence
from c2_analyzer.dom.form_features import form_features
from c2_analyzer.dom.link_features import link_features
from c2_analyzer.dom.vectorizer import build_vector
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.schemas.parsed_page import ParsedPage


def _group_features(group: str) -> list[str]:
    return [name for name, spec in specs().items() if spec.group == group]


def extract_dom_features(page: ParsedPage, html: str | None = None) -> DomResult:
    """Compute every DOM feature for one page (never raises for page content).

    ``html`` is the same (decoded, size-capped) HTML the ParsedPage was made
    from; without it, tree metrics come from the ParsedPage (with a warning).
    """
    started = time.perf_counter()
    dictionary = load_dictionary()
    values: dict[str, float | int] = {}
    details: dict[str, dict] = {}
    errors: list[str] = []
    warnings: list[str] = []
    page_url_known = bool(page.meta.page_url)

    def run(groups: tuple[str, ...], function: Callable[[], dict]) -> None:
        try:
            values.update(function())
        except Exception as error:  # noqa: BLE001 - one group must not lose the whole page
            errors.append(f"{'/'.join(groups)}: {type(error).__name__}: {error}")
            for group in groups:
                values.update({name: 0 for name in _group_features(group)})

    soup = None
    tree_source = "parsed_page"
    if html is not None:
        try:
            soup = dom_tree.parse(html)
            tree_source = "html"
        except Exception as error:  # noqa: BLE001 - fall back to Part 2's numbers
            errors.append(f"parse: {type(error).__name__}: {error}")
    if soup is None:
        warnings.append("tree metrics from the ParsedPage (raw HTML not available)")
        if page.meta.truncated and any("skeleton" in r for r in page.meta.truncation_reasons):
            warnings.append("avg_depth / leaf_ratio from a capped skeleton (approximate)")

    def structure() -> dict:
        measured = dom_tree.measure(soup) if soup is not None else dom_tree.from_parsed_page(page)
        html_bytes = page.meta.html_size_bytes
        return {
            "base_url_known": int(page_url_known),
            "node_count": measured.node_count,
            "element_count": measured.element_count,
            "max_depth": measured.max_depth,
            "avg_depth": measured.avg_depth,
            "leaf_ratio": measured.leaf_ratio,
            "distinct_tag_count": measured.distinct_tag_count,
            "text_to_html_ratio": (
                round(len(page.visible_text) / html_bytes, 4) if html_bytes else 0.0
            ),
        }

    def forms() -> dict:
        found, more = form_features(page, page_url_known)
        details.update(more)
        return found

    def elements() -> dict:
        found, more, notes = element_features(page, page_url_known, soup)
        details.update(more)
        warnings.extend(notes)
        return found

    def links() -> dict:
        found, more = link_features(page, page_url_known)
        details.update(more)
        return found

    run(("context", "structure"), structure)
    run(("forms", "credentials", "hidden_inputs", "form_actions"), forms)
    run(("iframes", "scripts", "hidden_elements"), elements)
    run(("links", "meta_resources"), links)
    if not page_url_known:
        warnings.append("page URL unknown: internal/external features are 0 (base_url_known=0)")

    features = build_vector(values)
    return DomResult(
        sample_id=page.meta.sample_id,
        dataset_version=page.meta.dataset_version,
        feature_set_version=dictionary.feature_set_version,
        dictionary_hash=dictionary_hash(),
        source_sha256=page.meta.source_sha256,
        tree_source=tree_source,
        features=features,
        evidence=build_evidence(features, details),
        errors=errors,
        warnings=warnings,
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
    )


def dom_features_for_html(html: str, url: str | None = None) -> DomResult:
    """The API path (Part 9): HTML string -> Part 2 -> Part 3, on the same capped HTML."""
    raw = from_string(html, url)
    return extract_dom_features(preprocess(raw), raw.html)
