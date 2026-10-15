"""Social-engineering intent taxonomy: load it, match cue words, weak-label a text.

Part 5: Multilingual scam content analyzer (Batch B, Task 10).

Why: the corpus needs ONE fixed list of intents (what a text tries to make the
reader do) that the builder, the review tool, the annotation guide and Part 6
all share. ``configs/intent_taxonomy.yaml`` is that list; this module loads and
validates it and turns its cue words into a WEAK labeller.

Weak labelling = a cheap first guess, never the final label: every intent whose
cue words occur in the text is suggested, ordered by the taxonomy's priority
(first = primary_intent). A person confirms or corrects it in
scripts/review_corpus.py. Matching rules (also documented in the YAML):
- text and cues are NFC, case-folded, whitespace-collapsed, ZWJ / ZWNJ removed
  (Sinhala conjuncts are written with and without them);
- a Latin-only cue matches whole words (regex word boundaries);
- a Sinhala / Tamil cue matches as a substring (the words are inflected).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from c2_analyzer.config import project_root

BENIGN = "benign"
CUE_LANGUAGES = ("en", "si", "ta")
LATIN_CUE = re.compile(r"^[a-z0-9 '%$.\-]+$")
SPACES = re.compile(r"\s+")
JOINERS = dict.fromkeys(map(ord, "‌‍"))  # ZWNJ, ZWJ -> removed for matching


def default_path() -> Path:
    return project_root() / "configs" / "intent_taxonomy.yaml"


def normalize_for_match(text: str) -> str:
    """The form both texts and cues are compared in (see the module docstring)."""
    text = unicodedata.normalize("NFC", text).translate(JOINERS).casefold()
    return SPACES.sub(" ", text).strip()


@dataclass(frozen=True)
class Intent:
    id: str
    definition: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    examples: tuple[str, ...]
    cues: dict[str, tuple[str, ...]]  # language -> cue phrases as written in the YAML


@dataclass
class Taxonomy:
    version: str
    intents: dict[str, Intent]  # in YAML order
    priority: tuple[str, ...]
    strong_min_hits: int
    file_hash: str  # sha256 of the YAML (recorded in corpus manifests)
    _patterns: list[tuple[str, str, re.Pattern | str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for intent in self.intents.values():
            for language in CUE_LANGUAGES:
                for cue in intent.cues.get(language, ()):
                    key = normalize_for_match(cue)
                    if LATIN_CUE.match(key):
                        pattern = re.compile(rf"(?<![\w]){re.escape(key)}(?![\w])")
                        self._patterns.append((intent.id, key, pattern))
                    else:
                        self._patterns.append((intent.id, key, key))

    @property
    def ids(self) -> list[str]:
        return list(self.intents)

    def rank(self, intents: list[str] | set[str]) -> list[str]:
        """Intents in priority order, benign dropped if anything else is present."""
        chosen = [name for name in self.priority if name in set(intents)]
        if len(chosen) > 1 and BENIGN in chosen:
            chosen.remove(BENIGN)
        return chosen or [BENIGN]

    def cue_hits(self, text: str) -> dict[str, list[str]]:
        """intent -> the distinct cue phrases found in ``text`` (normalized form)."""
        normalized = normalize_for_match(text)
        hits: dict[str, list[str]] = {}
        for intent_id, key, pattern in self._patterns:
            found = (
                pattern.search(normalized)
                if isinstance(pattern, re.Pattern)
                else (pattern in normalized)
            )
            if found and key not in hits.get(intent_id, []):
                hits.setdefault(intent_id, []).append(key)
        return hits


@dataclass
class WeakLabel:
    intents: list[str]  # priority order; first = primary
    cue_intents: list[str]  # what the cue words alone suggest (priority order)
    hits: int  # distinct cue phrases found (all intents)
    needs_review: bool = False
    note: str = ""

    @property
    def primary(self) -> str:
        return self.intents[0]


def weak_label(text: str, benign_page: bool = False, taxonomy: Taxonomy | None = None) -> WeakLabel:
    """Suggest intents for one text from the cue words.

    benign_page: the text comes from a page labelled benign. Then it stays
    "benign" unless a STRONG cue fires (>= ``strong_min_hits`` distinct cue
    phrases) - in that case it gets the cue intents and ``needs_review``,
    because genuine sites also say "verify your account".
    """
    taxonomy = taxonomy or load_taxonomy()
    hits = taxonomy.cue_hits(text)
    cue_intents = taxonomy.rank(set(hits)) if hits else [BENIGN]
    distinct = len({cue for cues in hits.values() for cue in cues})
    if not hits:
        return WeakLabel([BENIGN], cue_intents, 0)
    if benign_page and distinct < taxonomy.strong_min_hits:
        return WeakLabel([BENIGN], cue_intents, distinct, note="weak cue on a benign page ignored")
    if benign_page:
        note = f"strong cue on a benign page ({distinct} cue phrases)"
        return WeakLabel(cue_intents, cue_intents, distinct, needs_review=True, note=note)
    return WeakLabel(cue_intents, cue_intents, distinct)


# ---- loading + validation ------------------------------------------------------------------


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError(f"{where} must be a list of non-empty strings")
    return tuple(value)


def parse_taxonomy(data: dict[str, Any], file_hash: str = "") -> Taxonomy:
    """Validate the YAML content; ValueError with a readable message if it is wrong."""
    intents: dict[str, Intent] = {}
    for item in data.get("intents") or []:
        intent_id = item.get("id")
        if not intent_id or intent_id in intents:
            raise ValueError(f"intent id missing or repeated: {intent_id!r}")
        cues = item.get("cues") or {}
        unknown = set(cues) - set(CUE_LANGUAGES)
        if unknown:
            raise ValueError(f"{intent_id}: unknown cue language(s) {sorted(unknown)}")
        examples = _strings(item.get("examples"), f"{intent_id}.examples")
        if len(examples) < 2:
            raise ValueError(f"{intent_id}: needs at least 2 English examples")
        intents[intent_id] = Intent(
            id=intent_id,
            definition=str(item.get("definition", "")).strip(),
            include=_strings(item.get("include"), f"{intent_id}.include"),
            exclude=_strings(item.get("exclude"), f"{intent_id}.exclude"),
            examples=examples,
            cues={lang: tuple(cues.get(lang) or ()) for lang in CUE_LANGUAGES},
        )
        if not intents[intent_id].definition:
            raise ValueError(f"{intent_id}: definition is empty")
    if BENIGN not in intents:
        raise ValueError("the taxonomy must contain 'benign'")
    if any(intents[BENIGN].cues.values()):
        raise ValueError("benign has no cue words (benign = no other intent)")
    priority = tuple(data.get("priority") or ())
    if sorted(priority) != sorted(intents) or priority[-1] != BENIGN:
        raise ValueError("priority must list every intent exactly once, benign last")
    return Taxonomy(
        version=str(data.get("taxonomy_version", "")),
        intents=intents,
        priority=priority,
        strong_min_hits=int((data.get("weak_labelling") or {}).get("strong_min_hits", 2)),
        file_hash=file_hash,
    )


@lru_cache(maxsize=4)
def _load(path: Path) -> Taxonomy:
    raw = path.read_bytes()
    return parse_taxonomy(yaml.safe_load(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest())


def load_taxonomy(path: Path | None = None) -> Taxonomy:
    """The validated taxonomy (cached per file)."""
    return _load(Path(path) if path else default_path())


def intent_names() -> list[str]:
    """Ordered list of intent ids (YAML order)."""
    return load_taxonomy().ids
