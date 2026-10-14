"""Assemble the DOM security feature vector (task 13).

Part 3: DOM structural analysis.

Why: a classifier needs the same features in the same order for every page,
forever (within one feature_set_version). The order is the order of
configs/dom_features.yaml. ``build_vector`` refuses anything that would
silently corrupt training data: an unknown or missing feature name, or a
value that is not a finite number. Types are normalised (int / float /
binary 0-1) so the CSV is clean.
"""

from __future__ import annotations

import math

from c2_analyzer.dom.dictionary import feature_names, specs


class FeatureVectorError(ValueError):
    """The computed features do not match the dictionary (a bug, never page content)."""


def _coerce(name: str, kind: str, value: object) -> float | int:
    if isinstance(value, bool):
        value = int(value)
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        raise FeatureVectorError(f"feature {name!r} is not a finite number: {value!r}")
    if kind == "binary":
        if value not in (0, 1):
            raise FeatureVectorError(f"binary feature {name!r} must be 0 or 1, got {value!r}")
        return int(value)
    if kind == "int":
        return int(value)
    return round(float(value), 6)


def build_vector(values: dict[str, float | int]) -> dict[str, float | int]:
    """Ordered {name: value} exactly as the dictionary; raises on any mismatch."""
    declared = specs()
    unknown = sorted(set(values) - set(declared))
    missing = [name for name in declared if name not in values]
    if unknown or missing:
        raise FeatureVectorError(f"unknown features {unknown}, missing features {missing}")
    return {name: _coerce(name, spec.type, values[name]) for name, spec in declared.items()}


def to_list(features: dict[str, float | int]) -> list[float]:
    """The vector as a list of floats in dictionary order (for numpy / Part 4)."""
    return [float(features[name]) for name in feature_names()]


__all__ = ["FeatureVectorError", "build_vector", "feature_names", "to_list"]
