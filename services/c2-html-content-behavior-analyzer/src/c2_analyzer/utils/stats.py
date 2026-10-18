"""Small-sample proportion statistics shared by the evaluation reports (benchmark, fairness).

Why Wilson and not p ± 1.96·SE: with the small counts these reports deal in (3 real
keylogging pages, 12 Sinhala benign pages), the normal approximation gives intervals
below 0 or above 1 and a zero-width interval for 0/n or n/n. The Wilson score interval
stays inside [0, 1] and is honest about how little a handful of pages proves.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Proportion:
    k: int
    n: int
    rate: float | None  # None when n == 0
    low: float | None
    high: float | None

    def as_dict(self) -> dict:
        return {"k": self.k, "n": self.n, "rate": self.rate, "ci95": [self.low, self.high]}

    def text(self, digits: int = 1) -> str:
        """'3/10 = 30.0 % [10.8, 60.3]' (or 'n = 0')."""
        if not self.n:
            return "n = 0"
        pct = lambda v: f"{100 * v:.{digits}f}"  # noqa: E731
        return f"{self.k}/{self.n} = {pct(self.rate)} % [{pct(self.low)}, {pct(self.high)}]"


def wilson(k: int, n: int, z: float = 1.959964) -> Proportion:
    """Wilson score interval for k successes out of n (95 % by default)."""
    if k < 0 or n < 0 or k > n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")
    if n == 0:
        return Proportion(0, 0, None, None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    low = 0.0 if k == 0 else max(0.0, centre - half)  # exact at the edges (no 0.9999...)
    high = 1.0 if k == n else min(1.0, centre + half)
    return Proportion(k, n, p, low, high)
