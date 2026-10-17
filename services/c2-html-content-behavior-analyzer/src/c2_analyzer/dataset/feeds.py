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
    threatradar a FOLDER: ThreatRadar's Telegram / Reddit / domain-filter outputs
                (weak label from configs/threatradar_rules.yaml, or skipped)
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import random
import unicodedata
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from c2_analyzer.config import get_labels, get_sources, load_yaml_config
from c2_analyzer.dataset.candidates import Candidate, CandidateStore
from c2_analyzer.utils.script_detect import native_script_hint
from c2_analyzer.utils.url import extract_domain, normalize_url

PRUNE_PREFIX = "pruned_by_filter"

FEEDS = ("openphish", "phishtank", "urlhaus", "tranco", "manual", "threatradar")

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


# ---- URLhaus filter (lists in configs/url_filters.yaml) ---------------------------


@lru_cache
def _urlhaus_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(drop_tags, drop_extensions, page_extensions), lower-case, read once."""
    rules = load_yaml_config("url_filters")["urlhaus"]
    return tuple(
        frozenset(str(item).lower() for item in rules[key])
        for key in ("drop_tags", "drop_extensions", "page_extensions")
    )


def parse_tags(text: str | None) -> list[str]:
    """URLhaus tags "elf,Mirai" -> ["elf", "mirai"]. Also reads our notes "... tags=a,b"."""
    if not text:
        return []
    if "tags=" in text:
        text = text.split("tags=", 1)[1]
    return [tag.strip().lower() for tag in text.split(",") if tag.strip()]


def urlhaus_filter_reason(url: str, tags: list[str]) -> str | None:
    """Why a URLhaus link is NOT a web page we want, or None to keep it.

    1. a botnet/binary tag (elf, mirai, ...)
    2. the last path segment has a binary/CPU-architecture extension (sora.mipsel)
    3. a bare IP address plus one file name that is not a web page (http://1.2.3.4/sora)
    """
    drop_tags, drop_extensions, page_extensions = _urlhaus_rules()
    for tag in tags:
        if tag in drop_tags:
            return f"binary tag '{tag}'"

    parts = urlsplit(url)
    segments = [segment for segment in parts.path.split("/") if segment]
    last = segments[-1].lower() if segments else ""
    extension = last.rsplit(".", 1)[1] if "." in last else ""
    if extension in drop_extensions or last in drop_extensions:
        return f"binary file extension '{extension or last}'"

    host = parts.hostname or ""
    if _is_ip_address(host) and len(segments) == 1 and extension not in page_extensions:
        return "bare IP with a file name"
    return None


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


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
    """URLhaus CSV: keep url_status == online and skip links to files (see urlhaus_filter_reason).

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
        reason = urlhaus_filter_reason(row.get("url", ""), parse_tags(row.get("tags")))
        if reason:
            result.filtered[reason] += 1
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


# ---- ThreatRadar (ingestion/threat-radar) ------------------------------------------
#
# ThreatRadar is a teammate's scraper (Telegram channels, subreddits, newly registered
# domains). Its outputs have NO label, so each row gets a WEAK suggested label from
# configs/threatradar_rules.yaml (first matching rule) or is skipped - never "benign".
# Every imported row says where it came from and "check label" in its notes.

THREATRADAR_SOURCES = ("telegram", "reddit", "domain_filter")
THREATRADAR_FIELDS = ("url", "channel", "title", "matched_keywords")

# Skip reasons (keys of ImportResult.filtered).
SKIP_DUPLICATE = "duplicate"
SKIP_ALLOW_LISTED = "allow-listed"
SKIP_NO_RULE = "no rule matched"
SKIP_BEFORE_SINCE = "before --since"
SKIP_UNDATED = "undated (with --since)"
SKIP_OVER_LIMIT = "over --limit"


@dataclass(frozen=True)
class ThreatRadarRule:
    label: str
    name: str
    mimicry: bool
    keywords: tuple[str, ...]  # folded with _fold


@dataclass(frozen=True)
class ThreatRadarRules:
    """configs/threatradar_rules.yaml, validated."""

    sources: dict[str, dict]  # telegram -> {files, source, match_fields}
    rules: tuple[ThreatRadarRule, ...]
    brands: tuple[str, ...]
    allow_list: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> ThreatRadarRules:
        sources = data["sources"]
        for name, spec in sources.items():
            if name not in THREATRADAR_SOURCES:
                raise ValueError(f"threatradar_rules: unknown source {name!r}")
            if spec["source"] not in get_sources():
                raise ValueError(f"threatradar_rules: {name}.source {spec['source']!r} unknown")
            unknown = set(spec["match_fields"]) - set(THREATRADAR_FIELDS)
            if unknown:
                raise ValueError(f"threatradar_rules: {name}.match_fields {sorted(unknown)}")
        rules = []
        for rule in data["rules"]:
            if rule["label"] not in get_labels() or rule["label"] == "benign":
                raise ValueError(f"threatradar_rules: rule label {rule['label']!r} not allowed")
            keywords = tuple(_fold(str(keyword)) for keyword in rule.get("keywords") or ())
            rules.append(
                ThreatRadarRule(rule["label"], rule["name"], bool(rule.get("mimicry")), keywords)
            )
        return cls(
            sources=sources,
            rules=tuple(rules),
            brands=tuple(_fold(str(brand)) for brand in data.get("brands") or ()),
            allow_list=tuple(str(domain).lower().strip(".") for domain in data["allow_list"]),
        )


@lru_cache
def load_threatradar_rules() -> ThreatRadarRules:
    return ThreatRadarRules.from_dict(load_yaml_config("threatradar_rules"))


@dataclass
class ThreatRadarRow:
    """One URL from a ThreatRadar output, before any decision."""

    source: str  # telegram / reddit / domain_filter
    line: int
    url: str
    day: date | None
    fields: dict[str, str]  # THREATRADAR_FIELDS read by the keyword rules ("url" added later)
    context: str  # "channel @x message_id=12" - goes into the notes
    mimic_brand: str | None = None  # ThreatRadar's brand_mimicry reason (domain filter)


@dataclass
class ThreatRadarImport(ImportResult):
    """ImportResult plus rows read per source; ``filtered`` counts the skip reasons."""

    read: Counter = field(default_factory=Counter)
    missing_files: list[str] = field(default_factory=list)


def _fold(text: str) -> str:
    """Compare text like Part 5 does: NFC, case-folded, without ZWJ / ZWNJ."""
    folded = unicodedata.normalize("NFC", text).casefold()
    return folded.replace("‍", "").replace("‌", "")


def _parse_day(text: str | None) -> date | None:
    """ISO date or timestamp ("2026-10-17T08:00:00+00:00") -> date, else None."""
    try:
        return date.fromisoformat((text or "").strip()[:10])
    except ValueError:
        return None


def _url_or_domain(url: str | None, domain: str | None) -> str:
    """The row's URL; a bare domain becomes https://<domain>/."""
    url, domain = (url or "").strip(), (domain or "").strip().lower()
    if url:
        return url
    return f"https://{domain}/" if domain else ""


def _csv_dicts(path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    """CSV rows with the line each starts on (quoted titles may contain newlines)."""
    reader = csv.DictReader(io.StringIO(_read_text(path)))
    line = 2
    for row in reader:
        yield line, {key.strip(): (value or "").strip() for key, value in row.items() if key}
        line = reader.line_num + 1


def _telegram_rows(path: Path) -> Iterator[ThreatRadarRow]:
    """scraped/urls_only.csv: domain,url,channel,date,message_id,views,has_photo."""
    for line, row in _csv_dicts(path):
        channel = row.get("channel", "").lstrip("@")
        yield ThreatRadarRow(
            source="telegram",
            line=line,
            url=_url_or_domain(row.get("url"), row.get("domain")),
            day=_parse_day(row.get("date")),
            fields={"channel": channel},
            context=f"channel @{channel or '?'} message_id={row.get('message_id') or '?'}",
        )


def _reddit_rows(path: Path) -> Iterator[ThreatRadarRow]:
    """scraped/reddit_urls_only.csv: domain,url,subreddit,date,post_id,score,title."""
    for line, row in _csv_dicts(path):
        yield ThreatRadarRow(
            source="reddit",
            line=line,
            url=_url_or_domain(row.get("url"), row.get("domain")),
            day=_parse_day(row.get("date")),
            fields={"title": row.get("title", "")},
            context=f"r/{row.get('subreddit') or '?'} post_id={row.get('post_id') or '?'}",
        )


def _domain_filter_rows(path: Path) -> Iterator[ThreatRadarRow]:
    """filtered/filtered_domains_<YYYY-MM-DD>.json written by domainFilter.js."""
    payload = json.loads(_read_text(path))
    if not isinstance(payload, dict):
        raise ValueError("expected a JSON object with a 'domains' list")
    day = _parse_day(payload.get("filteredAt")) or _parse_day(path.stem.rsplit("_", 1)[-1])
    for number, item in enumerate(payload.get("domains") or [], start=1):
        if not isinstance(item, dict):
            continue
        reasons = [str(reason) for reason in item.get("reasons") or []]
        mimic = item.get("mimicBrand") or next(
            (r.split(":", 1)[1] for r in reasons if r.startswith("brand_mimicry:")), None
        )
        keywords = " ".join(str(keyword) for keyword in item.get("matchedKeywords") or [])
        yield ThreatRadarRow(
            source="domain_filter",
            line=number,
            url=_url_or_domain(None, item.get("domain")),
            day=day,
            fields={"matched_keywords": keywords},
            context=f"{path.name} reasons={','.join(reasons) or '?'}",
            mimic_brand=mimic,
        )


_ROW_READERS = {
    "telegram": _telegram_rows,
    "reddit": _reddit_rows,
    "domain_filter": _domain_filter_rows,
}


def is_allow_listed(url: str, allow_list: Iterable[str]) -> bool:
    """True if the URL's host is an allow-listed domain or one of its subdomains."""
    host = extract_domain(url) or ""
    return any(host == domain or host.endswith(f".{domain}") for domain in allow_list)


def suggest_threatradar_label(
    row: ThreatRadarRow, rules: ThreatRadarRules
) -> tuple[str, str, str | None] | None:
    """First matching rule -> (label, reason, matched keyword or None); None = no rule."""
    host = _fold(extract_domain(row.url) or "")
    fields = {**row.fields, "url": row.url}
    match_fields = rules.sources[row.source]["match_fields"]
    for rule in rules.rules:
        if rule.mimicry:
            if row.mimic_brand:
                return rule.label, f"brand mimicry of '{row.mimic_brand}'", None
            brand = next((brand for brand in rules.brands if brand in host), None)
            if brand:
                return rule.label, f"look-alike of '{brand}' in host", None
        for name in match_fields:
            text = _fold(fields.get(name) or "")
            keyword = next((keyword for keyword in rule.keywords if keyword in text), None)
            if keyword:
                return rule.label, f"{rule.name} '{keyword}' in {name}", keyword
    return None


def import_threatradar(
    data_dir: Path,
    since: date | None = None,
    sources: Iterable[str] | None = None,
    limit: int | None = None,
    known_urls: Iterable[str] = (),
    rules: ThreatRadarRules | None = None,
) -> ThreatRadarImport:
    """Read ThreatRadar's outputs under ``data_dir`` (ingestion/threat-radar/backend/data).

    ``known_urls``: URLs already queued or registered (candidates + metadata); they and
    repeats inside this import are skipped as duplicates (normalized URLs). A missing
    file is listed in ``missing_files``, not an error. ``limit`` caps the number of new
    candidates (sources in the given order). Nothing is fetched.
    """
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        raise FileNotFoundError(f"ThreatRadar data folder not found: {data_dir}")
    rules = rules or load_threatradar_rules()
    sources = tuple(sources or THREATRADAR_SOURCES)
    unknown = [name for name in sources if name not in rules.sources]
    if unknown:
        raise ValueError(
            f"unknown ThreatRadar source(s) {unknown}; choose from {', '.join(rules.sources)}"
        )

    result = ThreatRadarImport()
    seen = {normalize_url(url) for url in known_urls if url}
    for source in sources:
        spec = rules.sources[source]
        for pattern in spec["files"]:
            paths = sorted(data_dir.glob(pattern))
            if not paths:
                result.missing_files.append(f"{source}: {pattern}")
            for path in paths:
                try:
                    rows = list(_ROW_READERS[source](path))
                except (ValueError, csv.Error) as error:  # broken JSON / CSV
                    result.rejected.append(f"{path.name}: unreadable ({error})")
                    continue
                for row in rows:
                    result.read[source] += 1
                    _consider(row, path.name, spec["source"], since, limit, seen, rules, result)
    return result


def _consider(
    row: ThreatRadarRow,
    file_name: str,
    metadata_source: str,
    since: date | None,
    limit: int | None,
    seen: set[str],
    rules: ThreatRadarRules,
    result: ThreatRadarImport,
) -> None:
    """Decide one row: skip (counted per reason), reject (invalid) or keep."""
    if since is not None and row.day is None:
        result.filtered[SKIP_UNDATED] += 1
        return
    if since is not None and row.day < since:
        result.filtered[SKIP_BEFORE_SINCE] += 1
        return
    if not extract_domain(row.url):
        result.rejected.append(f"{file_name} line {row.line}: no host in {row.url!r}")
        return
    if is_allow_listed(row.url, rules.allow_list):
        result.filtered[SKIP_ALLOW_LISTED] += 1
        return
    key = normalize_url(row.url)
    if key in seen:
        result.filtered[SKIP_DUPLICATE] += 1
        return
    match = suggest_threatradar_label(row, rules)
    if match is None:
        result.filtered[SKIP_NO_RULE] += 1
        return
    if limit is not None and len(result.candidates) >= limit:
        result.filtered[SKIP_OVER_LIMIT] += 1
        return
    seen.add(key)

    label, reason, keyword = match
    fields = row.fields
    language = native_script_hint(
        fields.get("channel"), fields.get("title"), fields.get("matched_keywords"), keyword
    )
    seen_on = f"; seen {row.day.isoformat()}" if row.day else ""
    result.add(
        row.line,
        url=row.url,
        suggested_label=label,
        language_hint=language or "unknown",
        source=metadata_source,
        notes=f"ThreatRadar {row.source}: {reason} — check label; {row.context}{seen_on}",
    )


def import_feed(
    feed: str, path: Path, top: int | None = None, sample: int | None = None
) -> ImportResult:
    """Run the importer for ``feed`` on a local file (``threatradar``: a folder, defaults)."""
    path = Path(path)
    if feed == "threatradar":
        return import_threatradar(path)
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


def prune_candidates(candidates: CandidateStore, label: str | None = None) -> Counter:
    """Re-apply the import filters to PENDING candidates already in candidates.csv.

    Needed when the filters get stricter after URLs were imported. Removed
    candidates are kept (for the record) but marked "skipped" with
    "pruned_by_filter: <reason>". Only URLhaus candidates have filters.
    Changes are in memory: call ``candidates.save()`` afterwards.
    Returns the number pruned per reason.
    """
    df = candidates.df
    rows = df[(df["status"] == "pending") & (df["source"] == "urlhaus")]
    if label is not None:
        rows = rows[rows["suggested_label"] == label]

    pruned: Counter = Counter()
    for row in rows.to_dict("records"):
        reason = urlhaus_filter_reason(row["url"], parse_tags(row["notes"]))
        if reason:
            candidates.mark(
                row["url"], "skipped", error=f"{PRUNE_PREFIX}: {reason}", count_attempt=False
            )
            pruned[reason] += 1
    return pruned


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
