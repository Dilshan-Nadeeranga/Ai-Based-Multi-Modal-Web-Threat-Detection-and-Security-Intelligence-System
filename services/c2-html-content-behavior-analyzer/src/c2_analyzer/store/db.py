"""SQLite connection + schema migrations for the C2 results store.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why SQLite (viva): C2 runs as ONE process on one machine (team deployment), the data is
small (thousands of scans a day at most) and the queue must survive a restart. SQLite is
a single file (data/c2_results.db, git-ignored), needs no server, is ACID and is in the
Python standard library. WAL mode lets the terminal tools (review_live.py,
pull_threatradar.py, demo_ingest.py) read and write while the API is running. If C2
ever ran on several machines, the repository layer (repository.py) is the only code
that would change (e.g. to PostgreSQL).

Migrations: ``MIGRATIONS[i]`` turns schema version i into i + 1. The version is kept in
``PRAGMA user_version``; on every start ``connect`` applies the missing steps in one
transaction, so an old database file is upgraded in place and never rebuilt. Never edit
a released step - append a new one.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

MIGRATIONS: tuple[str, ...] = (
    # 0 -> 1: jobs, results, review queue
    """
    CREATE TABLE scan_jobs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        url             TEXT NOT NULL,
        normalized_url  TEXT,               -- NULL for html-mode checks (never deduplicated)
        source          TEXT NOT NULL CHECK (source IN
                          ('user', 'threatradar_push', 'threatradar_pull', 'api')),
        source_ref      TEXT NOT NULL DEFAULT '{}',   -- JSON: channel, message_id, ...
        status          TEXT NOT NULL CHECK (status IN
                          ('queued', 'running', 'done', 'failed', 'skipped_duplicate')),
        attempts        INTEGER NOT NULL DEFAULT 0,
        created_at      TEXT NOT NULL,      -- ISO 8601 UTC, sortable as text
        started_at      TEXT,
        finished_at     TEXT,
        error           TEXT,
        next_attempt_at TEXT,               -- a retried job waits until then
        duplicate_of    INTEGER REFERENCES scan_jobs(id),
        demo            INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX ix_jobs_queue ON scan_jobs (status, next_attempt_at, id);
    CREATE INDEX ix_jobs_url ON scan_jobs (normalized_url, finished_at);
    CREATE INDEX ix_jobs_created ON scan_jobs (created_at);

    CREATE TABLE scan_results (
        job_id           INTEGER PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
        analysis_id      TEXT NOT NULL,
        verdict          TEXT,               -- Legitimate | Suspicious | Malicious | NULL
        threat_class     TEXT,
        risk_score       INTEGER,
        status           TEXT NOT NULL,      -- ok | inconclusive | unreachable | error
        final_url_domain TEXT,
        page_language    TEXT,
        top_findings     TEXT NOT NULL DEFAULT '[]',  -- JSON list of {id, severity, title}
        full_response    TEXT NOT NULL,      -- the AnalysisResponse JSON (never raw HTML)
        created_at       TEXT NOT NULL
    );
    CREATE INDEX ix_results_created ON scan_results (created_at);

    CREATE TABLE review_queue (
        job_id        INTEGER PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
        reason        TEXT NOT NULL,
        state         TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'confirmed', 'rejected')),
        decided_label TEXT,
        decided_by    TEXT,
        decided_at    TEXT,
        exported_at   TEXT,                 -- written to a manual-feed CSV
        created_at    TEXT NOT NULL
    );
    CREATE INDEX ix_review_state ON review_queue (state, created_at);
    """,
)

SCHEMA_VERSION = len(MIGRATIONS)


def connect(path: Path | str) -> sqlite3.Connection:
    """Open (creating if needed) the database and bring its schema up to date.

    ``":memory:"`` works for tests. The connection may be used from several threads
    (the repository serializes access with a lock).
    """
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        str(path), timeout=10, check_same_thread=False, isolation_level=None
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    if str(path) != ":memory:":
        connection.execute("PRAGMA journal_mode = WAL")
    migrate(connection)
    return connection


def migrate(connection: sqlite3.Connection) -> int:
    """Apply every missing migration step; returns the schema version afterwards."""
    current = connection.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"results database schema v{current} is newer than this code (v{SCHEMA_VERSION})"
        )
    for version in range(current, SCHEMA_VERSION):
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in _statements(MIGRATIONS[version]):
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version + 1}")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    return SCHEMA_VERSION


def _statements(script: str) -> list[str]:
    """Split a migration script into statements (no ';' inside our literals)."""
    lines = [line.split("--", 1)[0] for line in script.splitlines()]
    return [part.strip() for part in "\n".join(lines).split(";") if part.strip()]
