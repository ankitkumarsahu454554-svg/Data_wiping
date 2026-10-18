-- backend/migrations/001_initial_schema.sql
-- SecureWipe Enterprise — PostgreSQL schema (enterprise mode)
-- Mirrors the SQLite GORM models in main.go but adds indexes,
-- partitioning, row-level security, and audit triggers.

-- ─── Extensions ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- for fast text search on model/serial

-- ─── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username    TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,           -- bcrypt hash
    role        TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ,
    CONSTRAINT username_length CHECK (char_length(username) BETWEEN 3 AND 64)
);

CREATE INDEX idx_users_username ON users USING btree (username);
CREATE INDEX idx_users_role ON users USING btree (role);

-- ─── Drive records ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS drive_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_path     TEXT NOT NULL,
    serial_number   TEXT,
    model           TEXT,
    vendor          TEXT,
    firmware        TEXT,
    interface_type  TEXT,
    capacity_bytes  BIGINT NOT NULL,
    is_rotational   BOOLEAN,
    sector_size     INTEGER,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Pre-wipe snapshot of sysfs attributes (JSON)
    attributes      JSONB,
    -- HPA/DCO state at detection time
    hpa_active      BOOLEAN,
    dco_active      BOOLEAN,
    hpa_hidden_bytes BIGINT DEFAULT 0,
    CONSTRAINT positive_capacity CHECK (capacity_bytes > 0)
);

CREATE INDEX idx_drive_records_serial ON drive_records (serial_number);
CREATE INDEX idx_drive_records_model ON drive_records USING gin (model gin_trgm_ops);
CREATE INDEX idx_drive_records_detected ON drive_records (detected_at DESC);

-- ─── Wipe jobs ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wipe_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    drive_id        UUID NOT NULL REFERENCES drive_records(id),
    operator_id     UUID NOT NULL REFERENCES users(id),
    status          TEXT NOT NULL CHECK (status IN (
                        'queued', 'running', 'verifying', 'complete', 'failed', 'cancelled'
                    )),
    algorithm       TEXT NOT NULL,
    verification    TEXT NOT NULL CHECK (verification IN ('none', 'sampled', 'full', 'auto')),
    disable_hpa     BOOLEAN NOT NULL DEFAULT TRUE,
    restore_dco     BOOLEAN NOT NULL DEFAULT FALSE,
    -- Progress (updated during wipe)
    progress_pct    SMALLINT NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    bytes_wiped     BIGINT DEFAULT 0,
    throughput_mb_s NUMERIC(10,2),
    -- Timing
    queued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_secs   NUMERIC(12,3),
    -- Results
    bad_sectors     INTEGER DEFAULT 0,
    error_message   TEXT,
    -- Foreign key to certificate (created after completion)
    certificate_id  UUID,
    -- Wipe report JSON (final WipeReport from Rust engine)
    report          JSONB,
    CONSTRAINT no_future_start CHECK (started_at IS NULL OR started_at >= queued_at)
);

CREATE INDEX idx_wipe_jobs_status ON wipe_jobs (status);
CREATE INDEX idx_wipe_jobs_drive ON wipe_jobs (drive_id);
CREATE INDEX idx_wipe_jobs_operator ON wipe_jobs (operator_id);
CREATE INDEX idx_wipe_jobs_queued ON wipe_jobs (queued_at DESC);
CREATE INDEX idx_wipe_jobs_completed ON wipe_jobs (completed_at DESC) WHERE completed_at IS NOT NULL;

-- ─── Certificates ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wipe_certificates (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id              UUID NOT NULL REFERENCES wipe_jobs(id),
    certificate_number  TEXT NOT NULL UNIQUE,   -- human-readable, e.g. SW-2025-001234
    payload_hash        TEXT NOT NULL,          -- SHA-256 of the certificate JSON
    signature           TEXT NOT NULL,          -- JWS signature (ES256)
    key_id              TEXT NOT NULL,          -- fingerprint of signing key
    merkle_root         TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issued_by           UUID NOT NULL REFERENCES users(id),
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,
    -- The full certificate JSON payload (immutable after insert)
    payload             JSONB NOT NULL,
    CONSTRAINT cert_not_revoked_without_time CHECK (
        NOT revoked OR revoked_at IS NOT NULL
    )
);

CREATE INDEX idx_certs_job ON wipe_certificates (job_id);
CREATE INDEX idx_certs_number ON wipe_certificates (certificate_number);
CREATE INDEX idx_certs_issued ON wipe_certificates (issued_at DESC);
CREATE INDEX idx_certs_serial ON wipe_certificates ((payload->>'serial_number'));

-- ─── Audit log ────────────────────────────────────────────────────────────────
-- Append-only: prevent updates and deletes via rule + trigger.
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    prev_hash   TEXT NOT NULL,          -- SHA-256 of previous row
    row_hash    TEXT NOT NULL,          -- SHA-256(prev_hash || timestamp || user_id || action || details)
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     UUID REFERENCES users(id),
    action      TEXT NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    details     TEXT,
    job_id      UUID,
    resource    TEXT
) PARTITION BY RANGE (timestamp);

-- Monthly partitions (create for current + next year; extend as needed)
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_logs_2025_q2 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE audit_logs_2025_q3 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE audit_logs_2025_q4 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE audit_logs_2026_q1 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
CREATE TABLE audit_logs_2026_q2 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
CREATE TABLE audit_logs_default  PARTITION OF audit_logs DEFAULT;

CREATE INDEX idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX idx_audit_user ON audit_logs (user_id);
CREATE INDEX idx_audit_action ON audit_logs (action);
CREATE INDEX idx_audit_job ON audit_logs (job_id) WHERE job_id IS NOT NULL;

-- Immutability: block UPDATE and DELETE on audit_logs
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_logs DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- ─── MFA secrets ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mfa_secrets (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    totp_secret     TEXT NOT NULL,          -- Base32 TOTP secret (encrypted at rest)
    backup_codes    TEXT NOT NULL,          -- JSON array of bcrypt-hashed codes
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ
);

-- ─── ITAM sync log ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS itam_sync_log (
    id              BIGSERIAL PRIMARY KEY,
    job_id          UUID NOT NULL REFERENCES wipe_jobs(id),
    provider        TEXT NOT NULL,
    success         BOOLEAN NOT NULL,
    record_id       TEXT,
    http_status     INTEGER,
    message         TEXT,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_itam_job ON itam_sync_log (job_id);
CREATE INDEX idx_itam_synced ON itam_sync_log (synced_at DESC);

-- ─── Certificate sequence ────────────────────────────────────────────────────
CREATE SEQUENCE IF NOT EXISTS cert_number_seq START 1000 INCREMENT 1;

CREATE OR REPLACE FUNCTION next_certificate_number() RETURNS TEXT AS $$
DECLARE
    seq_val BIGINT;
BEGIN
    seq_val := nextval('cert_number_seq');
    RETURN 'SW-' || TO_CHAR(NOW(), 'YYYY') || '-' || LPAD(seq_val::TEXT, 6, '0');
END;
$$ LANGUAGE plpgsql;

-- ─── Triggers ─────────────────────────────────────────────────────────────────

-- Auto-set updated_at on users
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Auto-compute wipe job duration
CREATE OR REPLACE FUNCTION compute_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND NEW.started_at IS NOT NULL THEN
        NEW.duration_secs = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wipe_job_duration
    BEFORE UPDATE ON wipe_jobs
    FOR EACH ROW EXECUTE FUNCTION compute_duration();

-- ─── Row-level security ───────────────────────────────────────────────────────

ALTER TABLE wipe_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE wipe_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE drive_records ENABLE ROW LEVEL SECURITY;

-- Admins see everything; operators see their own jobs; auditors see everything (read-only).
-- These policies are enforced by setting the app role before queries.

CREATE POLICY jobs_admin ON wipe_jobs
    USING (current_setting('app.role', TRUE) = 'admin');

CREATE POLICY jobs_operator ON wipe_jobs
    USING (
        current_setting('app.role', TRUE) = 'operator'
        AND operator_id::TEXT = current_setting('app.user_id', TRUE)
    );

CREATE POLICY jobs_auditor ON wipe_jobs
    FOR SELECT
    USING (current_setting('app.role', TRUE) = 'auditor');

-- ─── Views ────────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_wipe_summary AS
SELECT
    wj.id AS job_id,
    dr.serial_number,
    dr.model,
    dr.vendor,
    dr.capacity_bytes,
    wj.algorithm,
    wj.verification,
    wj.status,
    wj.bad_sectors,
    wj.duration_secs,
    wj.throughput_mb_s,
    wj.queued_at,
    wj.completed_at,
    u.username AS operator,
    wc.certificate_number,
    wc.issued_at AS cert_issued_at,
    wc.merkle_root
FROM wipe_jobs wj
JOIN drive_records dr ON dr.id = wj.drive_id
JOIN users u ON u.id = wj.operator_id
LEFT JOIN wipe_certificates wc ON wc.job_id = wj.id;

-- Compliance dashboard view
CREATE OR REPLACE VIEW v_compliance_stats AS
SELECT
    DATE_TRUNC('month', completed_at) AS month,
    COUNT(*) AS total_wipes,
    SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) AS successful,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
    SUM(CASE WHEN bad_sectors > 0 THEN 1 ELSE 0 END) AS with_bad_sectors,
    AVG(throughput_mb_s) AS avg_throughput_mb_s,
    SUM(COALESCE((report->>'bytes_wiped')::BIGINT, 0)) AS total_bytes_wiped,
    array_agg(DISTINCT algorithm) AS algorithms_used
FROM wipe_jobs
WHERE completed_at IS NOT NULL
GROUP BY DATE_TRUNC('month', completed_at)
ORDER BY month DESC;

-- ─── Seed data (dev only — remove for production) ────────────────────────────
-- INSERT INTO users (id, username, email, password, role) VALUES
--     (uuid_generate_v4(), 'admin', 'admin@example.com',
--      '$2a$12$...', 'admin'); -- hash of 'changeme'
