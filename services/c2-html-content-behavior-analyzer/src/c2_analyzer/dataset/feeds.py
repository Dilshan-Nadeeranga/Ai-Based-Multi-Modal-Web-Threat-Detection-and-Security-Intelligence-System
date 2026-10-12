"""Feed importers: turn downloaded URL lists into Candidates (stage 1 of collection).

Part 1: Multilingual dataset preparation (Batch B).

Why: each public feed has its own file format. These small parsers read a
LOCAL file you downloaded and convert every usable line into a validated
``Candidate`` with the right label and source. Importing never touches the
network - the optional ``download_feed`` helper is separate and explicit.

    feed        file format                         label
    openphish   text, one URL per line              phishing
    phishtank   CSV with a "url" column             phishing
    urlhaus     CSV with "#" comments, online only  malware_delivery
    tranco      CSV "rank,domain" (or .zip)         benign
    manual      CSV url,label,language_hint,source,notes  (you fill it)
"""

from __future__ import annotations

import csv
import random
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from c2_analyzer.config import load_yaml_config
from c2_analyzer.dataset.candidates import Candidate

FEEDS = ("openphish", "phishtank", "urlhaus", "tranco", "manual")

# Official download locations (used only by download_feed). PhishTank needs an
# account/API key, so it is downloaded by hand.
FEED_URLS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_online/",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}
FEED_FILENAMES = {
    "openphish": "openphish.txt",
    "urlhaus": "urlhaus_online.csv",
    "tranco": "tranco_top1m.csv.zip",
}
DOWNLOAD_TIMEOUT_SECONDS = 60

# URLhaus links that point straight at a file (not a web page) are useless for
# an HTML analyzer, so they are filtered out.
BINARY_EXTENSIONS = (
    ".exe", ".apk", ".zip", ".rar", ".msi", ".dll", ".bin", ".sh", ".jar", ".js",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".iso", ".7z",
)  # fmt: skip


@dataclass
class ImportResult:
    """What an importer produced.

    candidates: valid rows ready for CandidateStore.add_many
    rejected:   lines that could not be turned into a Candidate (with reason)
    filtered:   rows intentionally left out, counted per reason (e.g. "offline")
    """

    candidates: list[Candidate] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    filtered: Counter = field(default_factory=Counter)

    def add(self, line_number: int, **fields: object) -> None:
        """Validate one row and keep it, or record why it was rejected."""
        try:
            self.candidates.append(Candidate(**fields))
        except ValidationError as error:
            reasons = "; ".join(issue["msg"] for issue in error.errors())
            self.rejected.append(f"line {line_number}: {reasons}")


# ---- helpers -------------------------------------------------------------------


def _read_text(path: Path) -> str:
    """Read a feed file as text. A .zip is opened and its first file is read."""
    path = Path(path)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            data = archive.read(archive.namelist()[0])
    else:
        data = path.read_bytes()
    # utf-8-sig drops a BOM if present; bad bytes must not crash an import.
    return data.decode("utf-8-sig", errors="replace")


def _data_lines(text: str) -> list[tuple[int, str]]:
    """Non-empty, non-comment lines with their 1-based line numbers."""
    return [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _csv_rows(lines: list[tuple[int, str]]) -> tuple[list[str], list[tuple[int, dict]]]:
    """Parse (line_number, text) lines as CSV with a header; returns (header, rows)."""
    if not lines:
        return [], []
    header = [name.strip() for name in next(csv.reader([lines[0][1]]))]
    rows = []
    for number, line in lines[1:]:
        values = next(csv.reader([line]))
        # strict=False: a short/long malformed row must not crash the import; missing
        # columns then fail Candidate validation and the line is reported as rejected.
        cells = (value.strip() for value in values)
        rows.append((number, dict(zip(header, cells, strict=False))))
    return header, rows


def _require_columns(header: list[str], required: tuple[str, ...], feed: str) -> None:
    missing = [column for column in required if column not in header]
    if missing:
        raise ValueError(f"{feed} file is missing column(s) {missing}; found {header}")


# ---- importers -------------------------------------------------------------------


def parse_openphish(path: Path) -> ImportResult:
    """OpenPhish feed.txt: one phishing URL per line."""
    result = ImportResult()
    for number, line in _data_lines(_read_text(path)):
        result.add(number, url=line.strip(), suggested_label="phishing", source="openphish")
    return result


def parse_phishtank(path: Path) -> ImportResult:
    """PhishTank verified_online.csv: uses the "url" column."""
    result = ImportResult()
    header, rows = _csv_rows(_data_lines(_read_text(path)))
    _require_columns(header, ("url",), "phishtank")
    for number, row in rows:
        result.add(number, url=row.get("url", ""), suggested_label="phishing", source="phishtank")
    return result


def parse_urlhaus(path: Path) -> ImportResult:
    """URLhaus CSV: keep url_status == online and skip direct links to binary files.

    URLhaus puts its header inside a comment ("# id,dateadded,url,url_status,...").
    """
    text = _read_text(path)
    header_line = next(
        (
            line.lstrip("#").strip()
            for line in text.splitlines()
            if line.startswith("#") and "url_status" in line
        ),
        None,
    )
    lines = _data_lines(text)
    if header_line is not None:
        lines = [(0, header_line), *lines]
    header, rows = _csv_rows(lines)
    _require_columns(header, ("url", "url_status"), "urlhaus")

    result = ImportResult()
    for number, row in rows:
        if row.get("url_status", "").lower() != "online":
            result.filtered["not online"] += 1
            continue
        if urlsplit(row.get("url", "")).path.lower().endswith(BINARY_EXTENSIONS):
            result.filtered["direct link to a binary file"] += 1
            continue
        notes = f"urlhaus threat={row.get('threat', '')} tags={row.get('tags', '')}"
        result.add(
            number,
            url=row.get("url", ""),
            suggested_label="malware_delivery",
            source="urlhaus",
            notes=notes,
        )
    return result


def parse_tranco(
    path: Path, top: int = 1000, sample: int | None = None, seed: int | None = None
) -> ImportResult:
    """Tranco list "rank,domain": take the ``top`` N domains, optionally a random ``sample``.

    Popular sites are used as benign examples; each becomes ``https://<domain>/``.
    The random sample uses the project seed, so it is reproducible.
    """
    ranked = []
    for number, line in _data_lines(_read_text(path)):
        rank, _, domain = line.partition(",")
        if not rank.strip().isdigit():  # header row or junk
            continue
        ranked.append((int(rank), domain.strip(), number))
    ranked = sorted(ranked)[:top]

    if sample is not None and sample < len(ranked):
        if seed is None:
            seed = load_yaml_config("config")["project"]["random_seed"]
        ranked = sorted(random.Random(seed).sample(ranked, sample))

    result = ImportResult()
    for rank, domain, number in ranked:
        result.add(
            number,
            url=f"https://{domain}/",
            suggested_label="benign",
            source="tranco",
            notes=f"tranco rank {rank}",
        )
    return result


def parse_manual(path: Path) -> ImportResult:
    """Hand-made CSV: url,label,language_hint,source,notes (lines starting with # are ignored).

    For pages no feed covers: fake shops, crypto scams, Sinhala/Tamil scams.
    Empty language_hint -> "unknown"; empty source -> "manual".
    """
    header, rows = _csv_rows(_data_lines(_read_text(path)))
    _require_columns(header, ("url", "label"), "manual")
    result = ImportResult()
    for number, row in rows:
        result.add(
            number,
            url=row.get("url", ""),
            suggested_label=row.get("label", ""),
            language_hint=row.get("language_hint") or "unknown",
            source=row.get("source") or "manual",
            notes=row.get("notes") or None,
        )
    return result


def import_feed(
    feed: str, path: Path, top: int | None = None, sample: int | None = None
) -> ImportResult:
    """Run the importer for ``feed`` on a local file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Feed file not found: {path}")
    if feed == "openphish":
        return parse_openphish(path)
    if feed == "phishtank":
        return parse_phishtank(path)
    if feed == "urlhaus":
        return parse_urlhaus(path)
    if feed == "tranco":
        if top is None:
            top = load_yaml_config("config")["collection"]["tranco_top"]
        return parse_tranco(path, top=top, sample=sample)
    if feed == "manual":
        return parse_manual(path)
    raise ValueError(f"unknown feed {feed!r}; choose from {', '.join(FEEDS)}")


# ---- optional download helper (the only network code in this file) ---------------


def download_feed(feed: str, dest_dir: Path) -> Path:
    """Download a public feed file into ``dest_dir`` and return its path.

    Only fetches the list of URLs - it never visits the URLs inside it.
    """
    if feed not in FEED_URLS:
        raise ValueError(
            f"no automatic download for {feed!r}; download it by hand "
            f"(automatic: {', '.join(FEED_URLS)})"
        )
    dest = Path(dest_dir) / FEED_FILENAMES[feed]
    dest.parent.mkdir(parents=True, exist_ok=True)
    response = httpx.get(FEED_URLS[feed], timeout=DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True)
    response.raise_for_status()
    dest.write_bytes(response.content)
    return dest
