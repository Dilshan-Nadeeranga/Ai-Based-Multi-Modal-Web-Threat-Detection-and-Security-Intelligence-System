"""XLM-R tokenizer loading, encoding and token-length statistics (task 1).

Part 6: XLM-R content classification (6A, page level). PORTABLE module: copied into
the Colab bundle, so it must not import ``c2_analyzer`` (see ``nlp/__init__.py``).

Why XLM-RoBERTa (viva): one SentencePiece vocabulary (250k pieces) and one encoder
pre-trained on 100 languages (CC-100), including Sinhala and Tamil. A single model
reads English, Sinhala, Tamil and the ~21 % "other" pages (German, Russian, Chinese ...)
of v0.3 without a per-language pipeline. Known gap: romanized Sinhala / Tamil
(Singlish / Tanglish) is rare in CC-100.

Why the token statistics: XLM-R reads at most 512 tokens. Part 5A puts the most
telling text first ([TITLE] [CTA] [LABEL] [HEADING] [ALERT] ...), so truncation drops
the tail ([TEXT] paragraphs). The report says how many pages per language lose text,
because Sinhala / Tamil need more tokens per character than English.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def load_tokenizer(name_or_path: str) -> Any:
    """AutoTokenizer of a hub name (``xlm-roberta-base``) or a local model folder."""
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(str(name_or_path))


def encode(tokenizer: Any, texts: list[str], max_length: int = 512) -> Any:
    """Tokenize with truncation at ``max_length`` and no padding (the collator pads per
    batch, which is much faster than padding every page to 512)."""
    return tokenizer(list(texts), truncation=True, max_length=max_length, padding=False)


def token_lengths(tokenizer: Any, texts: list[str]) -> np.ndarray:
    """Full token count of each text (special tokens included, NOT truncated)."""
    if not texts:
        return np.zeros(0, dtype=int)
    encoded = tokenizer(list(texts), truncation=False, padding=False, verbose=False)
    return np.array([len(ids) for ids in encoded["input_ids"]], dtype=int)


def _describe(lengths: np.ndarray, max_length: int) -> dict:
    if not len(lengths):
        return {"n": 0}
    truncated = int((lengths > max_length).sum())
    return {
        "n": int(len(lengths)),
        "median": float(np.median(lengths)),
        "p90": float(np.percentile(lengths, 90)),
        "max": int(lengths.max()),
        "truncated": truncated,
        "truncated_share": round(truncated / len(lengths), 4),
    }


def token_length_stats(
    tokenizer: Any, examples: list[dict], max_length: int = 512, group_by: str = "language"
) -> dict:
    """Token-length summary overall, per ``group_by`` value and per split.

    ``examples`` are dicts with ``text`` and ``group_by`` (and optionally ``split``).
    """
    lengths = token_lengths(tokenizer, [example["text"] for example in examples])
    result = {"max_length": max_length, "overall": _describe(lengths, max_length)}
    for key in (group_by, "split"):
        values = np.array([str(example.get(key, "")) for example in examples])
        result[f"per_{key}"] = {
            value: _describe(lengths[values == value], max_length)
            for value in sorted(set(values.tolist()))
        }
    return result


def render_token_stats_md(stats: dict, title: str = "Token lengths") -> str:
    """Markdown table of ``token_length_stats``."""
    lines = [f"# {title}", "", f"max_length = {stats['max_length']} tokens", ""]
    header = "| group | n | median | p90 | max | truncated |"
    for name, groups in (("overall", {"all": stats["overall"]}),) + tuple(
        (key, value) for key, value in stats.items() if key.startswith("per_")
    ):
        lines += [f"## {name}", "", header, "|---|---:|---:|---:|---:|---:|"]
        for group, row in groups.items():
            if not row.get("n"):
                lines.append(f"| {group} | 0 | — | — | — | — |")
                continue
            lines.append(
                f"| {group} | {row['n']} | {row['median']:.0f} | {row['p90']:.0f} | "
                f"{row['max']} | {row['truncated']} ({100 * row['truncated_share']:.1f} %) |"
            )
        lines.append("")
    return "\n".join(lines)
