"""Build the multilingual text corpus under data/corpus/<lang>/.

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

from pathlib import Path


def build_corpus(parsed_dir: Path, corpus_dir: Path) -> dict[str, int]:
    """Extract text from ParsedPage JSON, route by language; return counts per language."""
    raise NotImplementedError
