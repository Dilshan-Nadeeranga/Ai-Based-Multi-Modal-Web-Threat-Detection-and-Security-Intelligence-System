"""PreprocessSettings: the Part 2 limits from configs/config.yaml -> preprocessing.

Part 2: HTML preprocessing pipeline.

Why: every cap (5 MB page, 500 KB script, 3000 skeleton nodes, ...) is a
tunable in one YAML section instead of a magic number in the code. Tests
can pass smaller limits to check the "truncated" behaviour quickly.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from functools import lru_cache

from c2_analyzer.config import load_yaml_config


@dataclass(frozen=True)
class PreprocessSettings:
    output_dir: str = "data/processed/parsed_html"
    reports_dir: str = "reports/preprocessing"
    workers: int = 4
    max_html_bytes: int = 5 * 1024 * 1024
    max_script_chars: int = 512_000
    max_handler_chars: int = 2048
    max_structured_chars: int = 50_000
    max_value_chars: int = 200
    max_url_chars: int = 2048
    max_link_text_chars: int = 200
    max_meta_content_chars: int = 1000
    comment_samples: int = 5
    comment_sample_chars: int = 200
    skeleton_max_nodes: int = 3000
    skeleton_max_depth: int = 40


@lru_cache
def default_settings() -> PreprocessSettings:
    """Settings from configs/config.yaml (missing keys keep the defaults above)."""
    section = load_yaml_config("config").get("preprocessing", {})
    known = {field.name for field in fields(PreprocessSettings)}
    return PreprocessSettings(**{key: value for key, value in section.items() if key in known})
