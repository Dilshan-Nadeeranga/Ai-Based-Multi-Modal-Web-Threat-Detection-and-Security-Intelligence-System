-- Ownership of ScamTrace analyses and C4 repository scans (owner = users.id).
-- Users are deactivated rather than deleted, so ON DELETE RESTRICT protects research records.

CREATE TABLE IF NOT EXISTS analysis_records (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id    VARCHAR(64) NOT NULL UNIQUE,
    user_id        UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    input          JSONB NOT NULL,
    overall_score  INTEGER,
    final_label    VARCHAR(50),
    result         JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analysis_records_user_created_idx
    ON analysis_records (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS code_audit_scans (
    scan_id         VARCHAR(64) PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    repository_url  TEXT NOT NULL,
    status          VARCHAR(20) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS code_audit_scans_user_created_idx
    ON code_audit_scans (user_id, created_at DESC);
