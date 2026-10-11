"""A small cross-process lock based on exclusive file creation.

Used so that two writers (API + CLI, or two CLI runs) can never allocate the
same sample ID or interleave dataset writes. Works on Windows and POSIX.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from types import TracebackType

from app.exceptions import DatasetLockError

logger = logging.getLogger(__name__)

_PROCESS_LOCKS: dict[Path, threading.Lock] = {}
_REGISTRY_LOCK = threading.Lock()


def _process_lock(path: Path) -> threading.Lock:
    with _REGISTRY_LOCK:
        return _PROCESS_LOCKS.setdefault(path, threading.Lock())


class FileLock:
    """Context manager holding ``path`` exclusively.

    A lock file older than ``stale_after_seconds`` is assumed to belong to a
    crashed writer and is removed.
    """

    def __init__(self, path: Path, timeout_seconds: float = 10.0, stale_after_seconds: float = 120.0) -> None:
        self.path = path.resolve()
        self.timeout_seconds = timeout_seconds
        self.stale_after_seconds = stale_after_seconds
        self._thread_lock = _process_lock(self.path)

    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout_seconds
        if not self._thread_lock.acquire(timeout=self.timeout_seconds):
            raise DatasetLockError()
        try:
            self._acquire_file(deadline)
        except BaseException:
            self._thread_lock.release()
            raise
        return self

    def _acquire_file(self, deadline: float) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                self._remove_if_stale()
                if time.monotonic() >= deadline:
                    logger.error("Timed out waiting for dataset lock %s", self.path.name)
                    raise DatasetLockError() from None
                time.sleep(0.05)
                continue
            except OSError as exc:
                logger.error("Could not create dataset lock %s: %s", self.path.name, exc)
                raise DatasetLockError() from exc
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"{os.getpid()} {time.time():.0f}\n")
            return

    def _remove_if_stale(self) -> None:
        try:
            age = time.time() - self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if age > self.stale_after_seconds:
            logger.warning("Removing stale dataset lock (%.0f s old)", age)
            self.path.unlink(missing_ok=True)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.path.unlink(missing_ok=True)
        finally:
            self._thread_lock.release()
