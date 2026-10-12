"""The three views of the dataset: all, usable and clean.

Part 1: Multilingual dataset preparation (Batch D, Task 13).

Why: the statistics, the version manifest and (later) the train/test splits
must agree on which rows count. Defining the views once, here, means the
numbers in my progress report are exactly the samples the models train on.

- "all":    every row in metadata.csv
- "usable": not excluded AND quality_flag in (ok, redirected_offsite)
- "clean":  usable AND is_duplicate_of is empty (one row per near-duplicate
            cluster) - this is what the models train on
"""

from __future__ import annotations

import pandas as pd

from c2_analyzer.dataset.quality import usable_flags

VIEWS = ("all", "usable", "clean")


def select_view(df: pd.DataFrame, view: str) -> pd.DataFrame:
    """Return the rows of a metadata table (strings, as in the CSV) that belong to ``view``."""
    if view not in VIEWS:
        raise ValueError(f"unknown view {view!r}; choose one of {', '.join(VIEWS)}")
    if view == "all":
        return df.copy()
    usable = (df["excluded"] != "true") & df["quality_flag"].isin(usable_flags())
    if view == "clean":
        usable &= df["is_duplicate_of"] == ""
    return df[usable].copy()
