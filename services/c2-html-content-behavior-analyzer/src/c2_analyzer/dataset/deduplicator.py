"""Near-duplicate clustering of dataset samples (MinHash + LSH + union-find).

Part 1: Multilingual dataset preparation (Batch C, Task 11).

Why: exact copies are already blocked by sha256 when a page is registered,
but scam pages are rarely byte-identical. The SAME phishing kit is deployed
on hundreds of domains with tiny differences (a different domain name in the
text, a tracking id, a timestamp). If one copy lands in the training set and
another in the test set, the model is tested on a page it has effectively
already seen: the scores look great but say nothing about new pages (data
leakage). So near-duplicates are grouped into clusters:

  * every sample gets a ``cluster_id`` (a page with no near-duplicate is a
    cluster of one). The train/val/test splits (Part 4/6) are grouped by
    cluster_id, so a cluster never spans train and test;
  * inside a cluster one representative is chosen and the others get
    ``is_duplicate_of=<representative>``;
  * a cluster whose pages have DIFFERENT labels is not marked; it is
    reported as a "label conflict" for manual review (one label is wrong).

How two pages are compared - two views of each page:
  a) text: visible text, lower-cased, digits removed, whitespace collapsed,
     split on whitespace (works for Sinhala/Tamil - no English-only
     tokenizer), then word 5-grams ("shingles");
  b) DOM: the sequence of tag names (html, head, title, body, div, ...) as
     tag 4-grams - the page's layout skeleton.
Similarity = Jaccard(A, B) = |A n B| / |A u B| of the shingle sets.
Comparing every pair is O(n^2), so MinHash signatures + LSH first find
candidate pairs quickly, then the exact Jaccard decides. Thresholds are in
configs/config.yaml (dedup).

Nothing is deleted: only cluster_id and is_duplicate_of are written, plus
reports/dataset_stats/dedup_report.json and .csv. Re-running recomputes both
fields from scratch, so dedup owns ``is_duplicate_of``.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd
from datasketch import MinHash, MinHashLSH
from tqdm import tqdm

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import load_page
from c2_analyzer.dataset.quality import usable_flags
from c2_analyzer.utils.io import atomic_write_csv

# Report only the first pairs of a huge cluster (a kit on 300 domains has ~45 000 pairs).
MAX_PAIRS_IN_REPORT = 50


# ---- settings ------------------------------------------------------------------


@dataclass
class DedupSettings:
    """Thresholds from configs/config.yaml -> dedup (see the comments there)."""

    num_perm: int = 128
    text_shingle_size: int = 5
    tag_shingle_size: int = 4
    text_threshold: float = 0.90
    dom_threshold: float = 0.95
    dom_min_text_similarity: float = 0.70
    lsh_threshold: float = 0.60

    @classmethod
    def from_config(cls) -> DedupSettings:
        config = load_yaml_config("config")["dedup"]
        return cls(
            num_perm=config["minhash_num_perm"],
            text_shingle_size=config["text_shingle_size"],
            tag_shingle_size=config["tag_shingle_size"],
            text_threshold=config["text_threshold"],
            dom_threshold=config["dom_threshold"],
            dom_min_text_similarity=config["dom_min_text_similarity"],
            lsh_threshold=config["lsh_threshold"],
        )

    def is_near_duplicate(self, text_similarity: float, dom_similarity: float) -> bool:
        """The rule: very similar text, OR identical layout with fairly similar text."""
        return text_similarity >= self.text_threshold or (
            dom_similarity >= self.dom_threshold and text_similarity >= self.dom_min_text_similarity
        )


# ---- fingerprints --------------------------------------------------------------


def normalize_text(text: str) -> str:
    """Lower-case, remove digits (any script), collapse whitespace."""
    text = re.sub(r"\d+", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def shingles(tokens: list[str], size: int) -> set[str]:
    """All runs of ``size`` consecutive tokens. A shorter list is one shingle."""
    if not tokens:
        return set()
    if len(tokens) < size:
        return {" ".join(tokens)}
    return {" ".join(tokens[i : i + size]) for i in range(len(tokens) - size + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    """|A n B| / |A u B| (0.0 when both are empty)."""
    union = len(a | b)
    return len(a & b) / union if union else 0.0


@dataclass
class Fingerprint:
    """The two shingle sets of one page plus its visible-text length."""

    text: set[str]
    dom: set[str]
    text_length: int


def fingerprint(visible_text: str, tags: list[str], settings: DedupSettings) -> Fingerprint:
    words = normalize_text(visible_text).split()
    return Fingerprint(
        text=shingles(words, settings.text_shingle_size),
        dom=shingles(tags, settings.tag_shingle_size),
        text_length=len(visible_text),
    )


def minhash(items: set[str], num_perm: int) -> MinHash:
    signature = MinHash(num_perm=num_perm)  # fixed default seed -> reproducible
    for item in items:
        signature.update(item.encode("utf-8"))
    return signature


# ---- clustering ----------------------------------------------------------------


class UnionFind:
    """Groups items connected by pairs: if A~B and B~C then A, B, C are one group."""

    def __init__(self, items: list[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]  # path halving: keeps trees flat
            item = self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[max(root_a, root_b)] = min(root_a, root_b)

    def groups(self) -> list[list[str]]:
        members: dict[str, list[str]] = {}
        for item in self.parent:
            members.setdefault(self.find(item), []).append(item)
        return [sorted(group) for group in members.values()]


def find_pairs(
    fingerprints: dict[str, Fingerprint], settings: DedupSettings
) -> list[tuple[str, str, float, float]]:
    """Near-duplicate pairs (id_a, id_b, text_similarity, dom_similarity), id_a < id_b."""
    lsh = MinHashLSH(threshold=settings.lsh_threshold, num_perm=settings.num_perm)
    signatures = {}
    for sample_id, fp in fingerprints.items():
        signatures[sample_id] = minhash(fp.text, settings.num_perm)
        lsh.insert(sample_id, signatures[sample_id])

    pairs = []
    for sample_id in sorted(fingerprints):
        for other in lsh.query(signatures[sample_id]):
            if other <= sample_id:  # each pair once, and never a page with itself
                continue
            a, b = fingerprints[sample_id], fingerprints[other]
            text_similarity = jaccard(a.text, b.text)  # exact check of the LSH guess
            dom_similarity = jaccard(a.dom, b.dom)
            if settings.is_near_duplicate(text_similarity, dom_similarity):
                pairs.append(
                    (sample_id, other, round(text_similarity, 4), round(dom_similarity, 4))
                )
    return pairs


def choose_representative(rows: list[dict], text_lengths: dict[str, int]) -> str:
    """Keep the best copy: verified first, then the longest visible text, then the oldest."""
    best = min(
        rows,
        key=lambda row: (
            row["verified"] != "true",
            -text_lengths.get(row["sample_id"], 0),
            row["collection_date"],
            row["sample_id"],  # final tie-break: deterministic
        ),
    )
    return best["sample_id"]


@dataclass
class Cluster:
    cluster_id: str
    members: list[str]
    labels: list[str]
    representative: str | None  # None for a label conflict
    pairs: list[tuple[str, str, float, float]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def conflict(self) -> bool:
        return len(self.labels) > 1


@dataclass
class DedupResult:
    clusters: list[Cluster]
    not_compared: dict[str, str]  # sample_id -> reason it was not compared
    duplicates: dict[str, str]  # sample_id -> its representative
    changed: int = 0  # metadata rows whose cluster_id / is_duplicate_of changed

    @property
    def multi_clusters(self) -> list[Cluster]:
        return [cluster for cluster in self.clusters if cluster.size > 1]

    @property
    def conflicts(self) -> list[Cluster]:
        return [cluster for cluster in self.clusters if cluster.conflict]

    def summary(self) -> dict:
        return {
            "samples": sum(cluster.size for cluster in self.clusters),
            "compared": sum(cluster.size for cluster in self.clusters) - len(self.not_compared),
            "not_compared": dict(Counter(self.not_compared.values())),
            "clusters": len(self.clusters),
            "clusters_with_near_duplicates": len(self.multi_clusters),
            "duplicates_marked": len(self.duplicates),
            "label_conflicts": len(self.conflicts),
        }


def run_dedup(
    store: MetadataStore,
    dry_run: bool = False,
    reports_dir: Path | None = None,
    settings: DedupSettings | None = None,
    show_progress: bool = False,
) -> DedupResult:
    """Cluster all samples, set cluster_id / is_duplicate_of and write the reports.

    With ``dry_run`` nothing is saved and no report is written.
    Only usable pages (not excluded, quality flag ok/redirected_offsite, file
    present, some visible text) are compared; every other sample becomes a
    cluster of one, so it still gets a cluster_id.
    """
    settings = settings or DedupSettings.from_config()
    rows = {row["sample_id"]: row for row in store.df.to_dict("records")}

    fingerprints: dict[str, Fingerprint] = {}
    not_compared: dict[str, str] = {}
    for sample_id, row in tqdm(rows.items(), unit="page", disable=not show_progress):
        file = store.raw_dir / row["file_path"]
        if row["excluded"] == "true":
            not_compared[sample_id] = "excluded"
        elif row["quality_flag"] not in usable_flags():
            not_compared[sample_id] = f"quality_flag {row['quality_flag']}"
        elif not file.is_file():
            not_compared[sample_id] = "file missing"
        else:
            view = load_page(file, row["final_url"] or row["source_url"])
            fp = fingerprint(view.text, view.tags, settings)
            if fp.text:
                fingerprints[sample_id] = fp
            else:
                not_compared[sample_id] = "no visible text"

    pairs = find_pairs(fingerprints, settings)
    groups = UnionFind(sorted(rows))
    for a, b, _, _ in pairs:
        groups.union(a, b)
    pairs_by_root: dict[str, list] = {}
    for pair in pairs:
        pairs_by_root.setdefault(groups.find(pair[0]), []).append(pair)

    text_lengths = {sample_id: fp.text_length for sample_id, fp in fingerprints.items()}
    clusters, duplicates = [], {}
    # Sorted by first member, so cluster ids are the same on every run of the same data.
    for number, members in enumerate(sorted(groups.groups()), start=1):
        labels = sorted({rows[member]["label"] for member in members})
        cluster = Cluster(
            cluster_id=f"cl_{number:06d}",
            members=members,
            labels=labels,
            representative=None,
            pairs=pairs_by_root.get(groups.find(members[0]), []),
        )
        if len(labels) == 1:
            cluster.representative = choose_representative(
                [rows[member] for member in members], text_lengths
            )
            for member in members:
                if member != cluster.representative:
                    duplicates[member] = cluster.representative
        clusters.append(cluster)

    result = DedupResult(clusters, not_compared, duplicates)
    for cluster in clusters:
        for member in cluster.members:
            new = {"cluster_id": cluster.cluster_id, "is_duplicate_of": duplicates.get(member)}
            old = {key: rows[member][key] or None for key in new}
            if new != old:
                store.update(member, **new)
                result.changed += 1

    if not dry_run:
        store.save()
        write_reports(result, store, reports_dir, settings)
    return result


def write_reports(
    result: DedupResult,
    store: MetadataStore,
    reports_dir: Path | None,
    settings: DedupSettings,
) -> tuple[Path, Path]:
    """Write dedup_report.json (summary, clusters with 2+ pages) and .csv (one row per sample)."""
    if reports_dir is None:
        reports_dir = resolve_path(Path(load_yaml_config("config")["dedup"]["reports_dir"]))
    reports_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "settings": asdict(settings),
        "summary": result.summary(),
        "label_conflicts": [
            {"cluster_id": c.cluster_id, "labels": c.labels, "members": c.members}
            for c in result.conflicts
        ],
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "size": c.size,
                "labels": c.labels,
                "label_conflict": c.conflict,
                "representative": c.representative,
                "members": c.members,
                "pair_count": len(c.pairs),
                "pairs": [
                    {"a": a, "b": b, "text_similarity": t, "dom_similarity": d}
                    for a, b, t, d in c.pairs[:MAX_PAIRS_IN_REPORT]
                ],
            }
            for c in result.multi_clusters
        ],
    }
    json_path = reports_dir / "dedup_report.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    labels = dict(zip(store.df["sample_id"], store.df["label"], strict=True))
    rows = [
        {
            "sample_id": member,
            "label": labels[member],
            "cluster_id": cluster.cluster_id,
            "cluster_size": cluster.size,
            "representative": cluster.representative or "",
            "is_duplicate_of": result.duplicates.get(member, ""),
            "label_conflict": str(cluster.conflict).lower(),
            "not_compared_reason": result.not_compared.get(member, ""),
        }
        for cluster in result.clusters
        for member in cluster.members
    ]
    columns = list(rows[0]) if rows else ["sample_id"]
    csv_path = reports_dir / "dedup_report.csv"
    atomic_write_csv(pd.DataFrame(rows, columns=columns), csv_path, columns)
    return json_path, csv_path
