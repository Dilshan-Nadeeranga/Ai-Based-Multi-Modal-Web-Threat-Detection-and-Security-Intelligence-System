"""The DOM feature table as a baseline feature source (the Part 4 default).

Part 4: DOM baseline classifier ("Baseline 1": DOM-only structural classification).

Later parts reuse Part 4's training / evaluation code with their own
``FeatureSource`` (Part 8: js_features + behavior_features). This one is the
DOM source: Part 3's dom_features.csv, checked against feature_dictionary.json
and the current configs/dom_features.yaml (data.load_feature_table).
"""

from __future__ import annotations

from c2_analyzer.classifiers.dom_baseline.common import FeatureSource, dom_descriptions
from c2_analyzer.classifiers.dom_baseline.data import load_feature_table
from c2_analyzer.dom.dictionary import dictionary_hash, feature_names, load_dictionary

DOM_SOURCE = FeatureSource(
    key="dom",
    title="DOM baseline (Baseline 1)",
    heading="Baseline 1 - DOM-only structural classification",
    short="Baseline 1 - DOM only",
    card_name="C2 DOM baseline (Baseline 1: DOM-only structural classification)",
    intended_use="Baseline for the ablation study (DOM-only vs NLP-only, behavior-only, "
    "fused). Research use on the C2 dataset; not a production detector.",
    config_section="dom_baseline",
    default_models_dir="models/dom_baseline",
    default_reports_dir="reports/dom_baseline",
    command="scripts/train_dom_baseline.py",
    train_command="{command} train --version {version}",
    all_command="{command} all --version {version}",
    produce_hint="extract_dom_features.py run --version {version}",
    load_table=load_feature_table,
    names=lambda: list(feature_names()),
    descriptions=dom_descriptions,
    feature_set_version=lambda: load_dictionary().feature_set_version,
    fingerprint=dictionary_hash,
)
