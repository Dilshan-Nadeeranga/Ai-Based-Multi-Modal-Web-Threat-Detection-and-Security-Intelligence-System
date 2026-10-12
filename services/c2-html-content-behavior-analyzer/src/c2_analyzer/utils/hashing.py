"""Hashing helpers: exact (sha256) and near-duplicate (simhash/minhash).

Shared (used across Parts 1-9).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    """Hex sha256 of raw bytes."""
    raise NotImplementedError


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file's contents."""
    raise NotImplementedError


def simhash(text: str) -> int:
    """64-bit simhash fingerprint of ``text``."""
    raise NotImplementedError


def minhash(text: str, num_perm: int = 128) -> Any:
    """datasketch MinHash of ``text`` shingles."""
    raise NotImplementedError
