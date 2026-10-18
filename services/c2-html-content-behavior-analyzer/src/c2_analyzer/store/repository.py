"""Repository: the ONLY code that reads / writes the results database.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Three tables (schema in db.py):
- ``scan_jobs``    one row per URL C2 was asked to analyze (queue + history);
- ``scan_results`` the stored AnalysisResponse of a finished job (never raw HTML);
- ``review_queue`` high-risk results waiting for a person (never auto-trained on).

Every public method is one short transaction behind a process-wide lock, so the API
threads, the asyncio worker (through ``asyncio.to_thread``) and the request handlers can
share one connection safely. Callers get plain dicts / dataclasses, never cursors.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from c2_analyzer.store.db import connect

JOB_SOURCES = ("user", "threatradar_push", "threatradar_pull", "api")
JOB_STATUSES = ("queued", "running", "done", "failed", "skipped_duplicate")
REVIEW_STATES = ("pending", "confirmed", "rejected")
# Results whose page was actually seen: another job for the same URL may reuse them.
REUSABLE_RESULT_STATUSES = ("ok", "inconclusive")


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(moment: datetime) -> str:
    """Fixed-width UTC timestamp, so text order == time order in SQL."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


@dataclass(frozen=True)
class Job:
    """A job claimed by the worker."""

    id: int
    url: str
    normalized_url: str | None
    source: str
    source_ref: dict
    attempts: int  # including the attempt that is starting now
    demo: bool


@dataclass(frozen=True)
class NewJob:
    """One row for ``create_jobs``."""

    url: str
    normalized_url: str | None
    source: str
    source_ref: dict
    status: str = "queued"
    duplicate_of: int | None = None
    demo: bool = False


class ResultsStore:
    """Thread-safe access to data/c2_results.db (or ``":memory:"`` in tests)."""

    def __init__(self, path: Path | str, clock: Callable[[], datetime] = utc_now) -> None:
        self.path = path
        self.clock = clock
        self._db = connect(path)
        self._lock = threading.RLock()

    def now(self) -> str:
        return iso(self.clock())

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction (BEGIN IMMEDIATE = take the write lock up front)."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def _query(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    # ---- queue -----------------------------------------------------------------------

    def reusable_job(self, normalized_url: str, since: str) -> int | None:
        """A job whose result can stand in for a new check of ``normalized_url``.

        Either still in flight (queued / running: its result will come) or finished
        since ``since`` with a page verdict (ok / inconclusive). Unreachable results are
        not reused - a timeout may be a hiccup. Demo rows never count.
        """
        rows = self._query(
            """
            SELECT j.id FROM scan_jobs j LEFT JOIN scan_results r ON r.job_id = j.id
            WHERE j.normalized_url = ? AND j.demo = 0 AND (
                j.status IN ('queued', 'running')
                OR (j.status = 'done' AND j.finished_at >= ? AND r.status IN (?, ?))
            )
            ORDER BY j.id DESC LIMIT 1
            """,
            (normalized_url, since, *REUSABLE_RESULT_STATUSES),
        )
        return rows[0]["id"] if rows else None

    def create_jobs(self, jobs: list[NewJob]) -> list[int]:
        """Insert jobs in one transaction; returns their ids in order."""
        now = self.now()
        ids = []
        with self._tx() as db:
            for job in jobs:
                if job.source not in JOB_SOURCES or job.status not in JOB_STATUSES:
                    raise ValueError(f"bad job source / status: {job.source} / {job.status}")
                finished = now if job.status == "skipped_duplicate" else None
                cursor = db.execute(
                    """
                    INSERT INTO scan_jobs (url, normalized_url, source, source_ref, status,
                        created_at, finished_at, next_attempt_at, duplicate_of, demo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.url,
                        job.normalized_url,
                        job.source,
                        json.dumps(job.source_ref, ensure_ascii=False),
                        job.status,
                        now,
                        finished,
                        now if job.status == "queued" else None,
                        job.duplicate_of,
                        int(job.demo),
                    ),
                )
                ids.append(cursor.lastrowid)
        return ids

    def queue_depth(self) -> int:
        return self._query("SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'queued'")[0]["n"]

    def job_counts(self) -> dict[str, int]:
        rows = self._query("SELECT status, COUNT(*) AS n FROM scan_jobs GROUP BY status")
        counts = {status: 0 for status in JOB_STATUSES}
        counts.update({row["status"]: row["n"] for row in rows})
        return counts

    def claim_next(self) -> Job | None:
        """Take the oldest due queued job: status running, attempts + 1 (atomic)."""
        now = self.now()
        with self._tx() as db:
            row = db.execute(
                """
                SELECT * FROM scan_jobs
                WHERE status = 'queued' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY next_attempt_at, id LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE scan_jobs SET status = 'running', attempts = attempts + 1, "
                "started_at = ?, error = NULL WHERE id = ?",
                (now, row["id"]),
            )
        return Job(
            id=row["id"],
            url=row["url"],
            normalized_url=row["normalized_url"],
            source=row["source"],
            source_ref=json.loads(row["source_ref"] or "{}"),
            attempts=row["attempts"] + 1,
            demo=bool(row["demo"]),
        )

    def requeue_running(self) -> int:
        """Restart recovery: jobs left 'running' by a crash go back to the queue."""
        with self._tx() as db:
            cursor = db.execute(
                "UPDATE scan_jobs SET status = 'queued', next_attempt_at = ?, "
                "error = 'requeued after restart' WHERE status = 'running'",
                (self.now(),),
            )
            return cursor.rowcount

    def retry_later(self, job_id: int, error: str, next_attempt_at: datetime) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE scan_jobs SET status = 'queued', error = ?, next_attempt_at = ? "
                "WHERE id = ?",
                (error[:500], iso(next_attempt_at), job_id),
            )

    def release(self, job_id: int) -> None:
        """Give a claimed job back without counting the attempt (e.g. models not loaded)."""
        with self._tx() as db:
            db.execute(
                "UPDATE scan_jobs SET status = 'queued', attempts = MAX(attempts - 1, 0) "
                "WHERE id = ?",
                (job_id,),
            )

    def fail(self, job_id: int, error: str) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE scan_jobs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?",
                (error[:500], self.now(), job_id),
            )

    # ---- results ---------------------------------------------------------------------

    def complete(self, job_id: int, response: dict[str, Any], summary: dict[str, Any]) -> str:
        """Store a finished job's AnalysisResponse; returns the finish time.

        ``summary`` = the indexed columns (verdict, threat_class, risk_score, status,
        final_url_domain, page_language, top_findings), built by the caller.
        """
        now = self.now()
        with self._tx() as db:
            _insert_result(db, job_id, response, summary, now)
            db.execute(
                "UPDATE scan_jobs SET status = 'done', finished_at = ?, error = NULL "
                "WHERE id = ?",
                (now, job_id),
            )
        return now

    def insert_finished(
        self, job: NewJob, response: dict[str, Any], summary: dict[str, Any]
    ) -> tuple[int, str]:
        """A job that is already analyzed (a user's /analyze check, a demo page): job +
        result in ONE transaction, so the worker can never pick it up half-written."""
        now = self.now()
        with self._tx() as db:
            cursor = db.execute(
                """
                INSERT INTO scan_jobs (url, normalized_url, source, source_ref, status,
                    attempts, created_at, started_at, finished_at, demo)
                VALUES (?, ?, ?, ?, 'done', 1, ?, ?, ?, ?)
                """,
                (
                    job.url,
                    job.normalized_url,
                    job.source,
                    json.dumps(job.source_ref, ensure_ascii=False),
                    now,
                    now,
                    now,
                    int(job.demo),
                ),
            )
            _insert_result(db, cursor.lastrowid, response, summary, now)
        return cursor.lastrowid, now

    def known_urls(self, normalized_urls: list[str]) -> set[str]:
        """Which of these normalized URLs have EVER been queued / analyzed (demo rows not)."""
        found: set[str] = set()
        unique = sorted(set(normalized_urls))
        for start in range(0, len(unique), 500):
            chunk = unique[start : start + 500]
            rows = self._query(
                "SELECT DISTINCT normalized_url FROM scan_jobs WHERE demo = 0 AND normalized_url "
                f"IN ({', '.join('?' * len(chunk))})",
                chunk,
            )
            found.update(row["normalized_url"] for row in rows)
        return found

    def job(self, job_id: int) -> dict | None:
        rows = self._query("SELECT * FROM scan_jobs WHERE id = ?", (job_id,))
        return _job_dict(rows[0]) if rows else None

    def result(self, job_id: int) -> dict | None:
        """The stored response of a job; a skipped duplicate answers with its original's."""
        seen = set()
        while job_id is not None and job_id not in seen:
            seen.add(job_id)
            rows = self._query(
                "SELECT j.duplicate_of, r.full_response FROM scan_jobs j "
                "LEFT JOIN scan_results r ON r.job_id = j.id WHERE j.id = ?",
                (job_id,),
            )
            if not rows:
                return None
            if rows[0]["full_response"] is not None:
                return json.loads(rows[0]["full_response"])
            job_id = rows[0]["duplicate_of"]
        return None

    def list_scans(
        self,
        *,
        source: str | None = None,
        verdict: str | None = None,
        threat_class: str | None = None,
        since: str | None = None,
        q: str | None = None,
        limit: int = 50,
        before_id: int | None = None,
    ) -> list[dict]:
        """Finished scans, newest first (keyset pagination on the job id)."""
        where, params = ["1 = 1"], []
        if source:
            where.append("j.source = ?")
            params.append(source)
        if verdict == "none":
            where.append("r.verdict IS NULL")
        elif verdict:
            where.append("r.verdict = ?")
            params.append(verdict)
        if threat_class:
            where.append("r.threat_class = ?")
            params.append(threat_class)
        if since:
            where.append("j.created_at >= ?")
            params.append(since)
        if q:
            pattern = (
                "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            )
            where.append(
                "(LOWER(j.url) LIKE ? ESCAPE '\\' OR LOWER(r.final_url_domain) LIKE ? ESCAPE '\\')"
            )
            params += [pattern, pattern]
        if before_id is not None:
            where.append("j.id < ?")
            params.append(before_id)
        rows = self._query(
            f"""
            SELECT j.id, j.url, j.source, j.created_at, j.demo, r.verdict, r.threat_class,
                   r.risk_score, r.page_language, r.status, r.final_url_domain,
                   r.created_at AS analyzed_at
            FROM scan_jobs j JOIN scan_results r ON r.job_id = j.id
            WHERE {' AND '.join(where)}
            ORDER BY j.id DESC LIMIT ?
            """,
            [*params, limit],
        )
        return [dict(row) for row in rows]

    def window_rows(self, since: str) -> list[dict]:
        """Every finished scan since ``since`` (for the overview statistics)."""
        rows = self._query(
            """
            SELECT j.id, j.source, j.source_ref, j.created_at, r.verdict, r.threat_class,
                   r.risk_score, r.page_language, r.status, r.final_url_domain
            FROM scan_jobs j JOIN scan_results r ON r.job_id = j.id
            WHERE j.created_at >= ?
            """,
            (since,),
        )
        return [dict(row) for row in rows]

    def duplicates_since(self, since: str) -> int:
        rows = self._query(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'skipped_duplicate' "
            "AND created_at >= ?",
            (since,),
        )
        return rows[0]["n"]

    # ---- review queue ----------------------------------------------------------------

    def add_review(self, job_id: int, reason: str) -> bool:
        """Queue a result for a person, unless its URL is already pending / confirmed."""
        with self._tx() as db:
            row = db.execute(
                "SELECT normalized_url FROM scan_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                return False
            if row["normalized_url"]:
                taken = db.execute(
                    """
                    SELECT 1 FROM review_queue q JOIN scan_jobs j ON j.id = q.job_id
                    WHERE j.normalized_url = ? AND q.state IN ('pending', 'confirmed')
                    """,
                    (row["normalized_url"],),
                ).fetchone()
                if taken:
                    return False
            cursor = db.execute(
                "INSERT OR IGNORE INTO review_queue (job_id, reason, created_at) VALUES (?, ?, ?)",
                (job_id, reason, self.now()),
            )
            return cursor.rowcount == 1

    def reviews(self, state: str | None = "pending", limit: int | None = None) -> list[dict]:
        sql = """
            SELECT q.*, j.url, j.source, j.source_ref, j.demo, r.analysis_id, r.verdict,
                   r.threat_class, r.risk_score, r.page_language, r.final_url_domain,
                   r.top_findings
            FROM review_queue q JOIN scan_jobs j ON j.id = q.job_id
            JOIN scan_results r ON r.job_id = q.job_id
        """
        params: list = []
        if state:
            sql += " WHERE q.state = ?"
            params.append(state)
        sql += " ORDER BY q.created_at, q.job_id"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        result = []
        for row in self._query(sql, params):
            item = dict(row)
            item["source_ref"] = json.loads(item["source_ref"] or "{}")
            item["top_findings"] = json.loads(item["top_findings"] or "[]")
            result.append(item)
        return result

    def review_counts(self) -> dict[str, int]:
        rows = self._query("SELECT state, COUNT(*) AS n FROM review_queue GROUP BY state")
        counts = {state: 0 for state in REVIEW_STATES}
        counts.update({row["state"]: row["n"] for row in rows})
        return counts

    def decide_review(self, job_id: int, state: str, label: str | None, by: str) -> None:
        if state not in REVIEW_STATES:
            raise ValueError(f"unknown review state {state!r}")
        with self._tx() as db:
            cursor = db.execute(
                "UPDATE review_queue SET state = ?, decided_label = ?, decided_by = ?, "
                "decided_at = ?, exported_at = NULL WHERE job_id = ?",
                (state, label, by, self.now(), job_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"job {job_id} is not in the review queue")

    def mark_exported(self, job_ids: list[int]) -> None:
        now = self.now()
        with self._tx() as db:
            db.executemany(
                "UPDATE review_queue SET exported_at = ? WHERE job_id = ?",
                [(now, job_id) for job_id in job_ids],
            )

    # ---- maintenance -----------------------------------------------------------------

    def delete_demo(self) -> int:
        """Remove demo jobs (and, by cascade, their results and reviews)."""
        with self._tx() as db:
            db.execute(
                "UPDATE scan_jobs SET duplicate_of = NULL WHERE duplicate_of IN "
                "(SELECT id FROM scan_jobs WHERE demo = 1)"
            )
            return db.execute("DELETE FROM scan_jobs WHERE demo = 1").rowcount


def _job_dict(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["source_ref"] = json.loads(item.get("source_ref") or "{}")
    item["demo"] = bool(item.get("demo"))
    return item


def _insert_result(
    db: sqlite3.Connection, job_id: int, response: dict, summary: dict, now: str
) -> None:
    db.execute(
        """
        INSERT OR REPLACE INTO scan_results (job_id, analysis_id, verdict, threat_class,
            risk_score, status, final_url_domain, page_language, top_findings,
            full_response, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            response["analysis_id"],
            summary.get("verdict"),
            summary.get("threat_class"),
            summary.get("risk_score"),
            summary["status"],
            summary.get("final_url_domain"),
            summary.get("page_language"),
            json.dumps(summary.get("top_findings") or [], ensure_ascii=False),
            json.dumps(response, ensure_ascii=False),
            now,
        ),
    )
