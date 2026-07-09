-- Migration: 006_protected_cidrs
-- Description: Per-host protected CIDRs that cannot be blocked by rule pushes (SEC-006)
-- Prevents management-interface lockout.

CREATE TABLE IF NOT EXISTS host_protected_cidrs (
    host_id    UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cidr       INET NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_protected_cidrs_host ON host_protected_cidrs (host_id);