-- Migration: 011_audit_external_anchor
-- Description: External audit chain anchoring (SEC-004)
-- Records daily exports of the audit chain head to a write-once external store.

CREATE TABLE IF NOT EXISTS audit_anchor (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_head   TEXT NOT NULL,
    anchored_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anchor_type  TEXT NOT NULL CHECK (anchor_type IN ('s3_object_lock', 'rfc3161_tsa', 'remote_log_host')),
    anchor_ref   TEXT NOT NULL,
    verified_at  TIMESTAMPTZ,
    verified_ok  BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_audit_anchor_anchored ON audit_anchor (anchored_at DESC);