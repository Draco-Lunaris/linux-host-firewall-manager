-- Migration: 015_per_host_lock
-- Description: Per-host push serialization (SEC-013)
-- Prevents concurrent rule deploys to the same host.

CREATE TABLE IF NOT EXISTS host_apply_locks (
    host_id       UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    locked_by_job UUID REFERENCES firewall_jobs(id) ON DELETE SET NULL,
    locked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);