"""Remove HTML comments (Task 3) and summarise CSS (Task 4).

Part 2: HTML preprocessing pipeline.

Why:
- Comments are never shown to the visitor, so they must not end up in the
  page text. But phishing kits often leave comments ("<!-- kit by xyz -->",
  old code), so they are counted and the first few kept as metadata.
- CSS is about how the page LOOKS, not what it says. <style> blocks and
  stylesheet links are summarised (counts, sizes, where they come from) and
  their content is not used as text. ``style="..."`` attributes are left in
  the tree on purpose: Part 3 needs them to find hidden elements.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Comment

from c2_analyzer.preprocessing.settings import PreprocessSettings
from c2_analyzer.preprocessing.text_utils import normalize_inline, truncate
from c2_analyzer.schemas.parsed_page import CommentSummary, CssSummary, Stylesheet
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import is_external, registrable_domain, resolve_url


def remove_comments(soup: BeautifulSoup, settings: PreprocessSettings) -> CommentSummary:
    """Take every comment out of the tree; return how many there were and a few samples."""
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    samples = []
    total = 0
    for comment in comments:
        text = str(comment)
        total += len(text)
        if len(samples) < settings.comment_samples:
            samples.append(truncate(normalize_inline(text), settings.comment_sample_chars))
        comment.extract()
    return CommentSummary(count=len(comments), total_chars=total, samples=samples)


def summarize_css(
    soup: BeautifulSoup, base_url: str | None, page_url: str | None, settings: PreprocessSettings
) -> CssSummary:
    """Counts of <style> blocks and style attributes, plus external stylesheet links."""
    blocks = soup.find_all("style")
    stylesheets = []
    for link in soup.find_all("link", href=True):
        rel = link.get("rel") or []
        rel = rel if isinstance(rel, list) else str(rel).split()
        if "stylesheet" not in [value.lower() for value in rel]:
            continue
        href = resolve_url(link["href"], base_url)
        stylesheets.append(
            Stylesheet(
                href_abs=truncate(mask_url(href), settings.max_url_chars),
                domain=registrable_domain(href),
                is_external=is_external(href, page_url),
            )
        )
    return CssSummary(
        inline_style_blocks_count=len(blocks),
        inline_style_total_chars=sum(len(block.get_text()) for block in blocks),
        style_attribute_count=len(soup.find_all(style=True)),
        external_stylesheets=stylesheets,
    )
