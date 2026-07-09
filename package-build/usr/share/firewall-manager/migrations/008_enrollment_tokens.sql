-- Migration: 008_enrollment_tokens
-- Description: One-time per-host enrollment tokens (SEC-002)
-- Admin generates a token bound to a host FQDN; agent presents it with CSR.

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash  TEXT PRIMARY KEY,
    host_fqdn   TEXT NOT NULL,
    host_ip     INET,
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_fqdn ON enrollment_tokens (host_fqdn);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expires ON enrollment_tokens (expires_at) WHERE used_at IS NULL;