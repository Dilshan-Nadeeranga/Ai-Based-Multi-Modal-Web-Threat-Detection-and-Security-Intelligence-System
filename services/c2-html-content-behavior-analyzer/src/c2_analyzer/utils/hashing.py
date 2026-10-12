"""Hashing helpers: exact (sha256) and near-duplicate (simhash/minhash).

Shared (used across Parts 1-9).

Why: sha256 gives every file a content fingerprint. Two files with the same
sha256 are byte-for-byte identical, which is how Part 1 rejects exact
duplicates and detects files that changed after they were registered.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

# Read files in 1 MiB pieces so large pages never have to fit in memory at once.
CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Hex sha256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file's contents, read in chunks (streamed)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def simhash(text: str) -> int:
    """64-bit simhash fingerprint of ``text``."""
    raise NotImplementedError


def minhash(text: str, num_perm: int = 128) -> Any:
    """datasketch MinHash of ``text`` shingles."""
    raise NotImplementedError
