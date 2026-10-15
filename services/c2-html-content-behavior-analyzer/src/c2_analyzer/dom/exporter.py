"""Export DOM features to CSV / JSON (task 14).

Part 3: DOM structural analysis.

Why: Part 4 trains on ONE table, so its layout is fixed here:

    data/processed/dom_features/<version>/dom_features.csv
        sample_id, label, language, cluster_id, <features in dictionary order>
    data/processed/dom_features/<version>/<sample_id>.json      full DomResult + evidence
    data/processed/dom_features/<version>/feature_dictionary.json  the dictionary used

cluster_id is kept so Part 4 can split by near-duplicate cluster (Part 1 rule).
All writes are atomic (a crash never leaves half a file).
"""

from __future__ import annotations

import io
from pathlib import Path

import pandas as pd

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.dom.dictionary import dictionary_hash, feature_names, load_dictionary
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.utils.io import atomic_write_text, write_json

ID_COLUMNS = ["sample_id", "label", "language", "cluster_id"]
CSV_NAME = "dom_features.csv"
DICTIONARY_NAME = "feature_dictionary.json"


def _config() -> dict:
    return load_yaml_config("config").get("dom_features", {})


def output_dir(version: str | None) -> Path:
    """data/processed/dom_features/<version or "adhoc">/"""
    base = _config().get("output_dir", "data/processed/dom_features")
    return resolve_path(Path(base)) / (version or "adhoc")


def reports_dir() -> Path:
    return resolve_path(Path(_config().get("reports_dir", "reports/dom_features")))


def csv_columns() -> list[str]:
    return ID_COLUMNS + list(feature_names())


def feature_frame(rows: list[dict]) -> pd.DataFrame:
    """Rows ({sample_id, label, language, cluster_id, features: {...}}) -> table in CSV order."""
    records = [
        {**{column: row.get(column, "") for column in ID_COLUMNS}, **row["features"]}
        for row in rows
    ]
    return pd.DataFrame.from_records(records, columns=csv_columns())


def export_csv(rows: list[dict], path: Path) -> Path:
    """Write the feature table (ID columns, then features in dictionary order)."""
    buffer = io.StringIO()
    feature_frame(rows).to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), path)
    return path


def export_json(result: DomResult, path: Path) -> Path:
    """One page's full DomResult (features + evidence) as JSON."""
    atomic_write_text(result.model_dump_json(indent=1), path)
    return path


def export_dictionary(path: Path) -> Path:
    """A copy of the dictionary the features were made with (+ its hash)."""
    dictionary = load_dictionary()
    write_json({"dictionary_hash": dictionary_hash(), **dictionary.raw}, path)
    return path
