"""Complementarity of the modalities: which arms got each test page right.

Part 9: Tri-modal fusion + ablation study (Batch A, task 4).

Why (viva): fusion can only beat the best single arm if the arms make DIFFERENT mistakes.
For every test page we record which modality's argmax was right and count the buckets
("only DOM right", "only text right", "only behavior right", "all wrong", ...). Pages that
only one modality gets right are exactly where fusion can help; pages that all get wrong
are a limit no fusion of these arms can fix (look at them in the inspector). The final
fusion model's answer is shown for each bucket too: how many "only-one-right" pages did it
rescue, how many "all right" pages did it break.
"""

from __future__ import annotations

import numpy as np

MODALITIES = ("dom", "behavior", "text")
NAMES = {"dom": "DOM", "behavior": "behavior", "text": "text"}


def bucket_of(correct: dict[str, bool]) -> str:
    right = [m for m in MODALITIES if correct.get(m)]
    present = [m for m in MODALITIES if m in correct]
    if len(right) == len(present):
        return "all_right"
    if not right:
        return "all_wrong"
    if len(right) == 1:
        return f"only_{right[0]}_right"
    wrong = [m for m in present if m not in right]
    return f"only_{wrong[0]}_wrong" if len(wrong) == 1 else "+".join(right) + "_right"


BUCKET_ORDER = (
    "all_right",
    "only_dom_right",
    "only_behavior_right",
    "only_text_right",
    "only_dom_wrong",
    "only_behavior_wrong",
    "only_text_wrong",
    "all_wrong",
)


def complementarity(
    sample_ids: list[str],
    y: np.ndarray,
    predictions: dict[str, np.ndarray],
    fused: np.ndarray | None = None,
    examples: int = 5,
) -> dict:
    """Bucket counts + up to ``examples`` sample ids per bucket (sorted, so stable).

    ``predictions`` = modality ("dom" / "behavior" / "text") -> argmax predictions on the
    test pages; ``fused`` = the final fusion model's predictions (optional).
    """
    y = np.asarray(y)
    correct = {m: np.asarray(p) == y for m, p in predictions.items()}
    buckets: dict[str, list[int]] = {}
    for i in range(len(y)):
        buckets.setdefault(bucket_of({m: bool(c[i]) for m, c in correct.items()}), []).append(i)
    order = [b for b in BUCKET_ORDER if b in buckets] + sorted(set(buckets) - set(BUCKET_ORDER))
    result = {}
    for bucket in order:
        index = buckets[bucket]
        ids = sorted(sample_ids[i] for i in index)
        entry = {"count": len(index), "examples": ids[:examples]}
        if fused is not None:
            entry["fusion_right"] = int((np.asarray(fused)[index] == y[index]).sum())
        result[bucket] = entry
    return {
        "modalities": list(predictions),
        "n": int(len(y)),
        "buckets": result,
        "oracle_accuracy": float(np.mean(np.any(np.stack(list(correct.values())), axis=0))),
    }
