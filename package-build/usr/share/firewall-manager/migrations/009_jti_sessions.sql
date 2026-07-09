-- Migration: 009_jti_sessions
-- Description: JWT jti revocation support (SEC-011)
-- Add jti column to refresh_tokens for blacklist tracking.

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS jti TEXT;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_jti ON refresh_tokens (jti) WHERE revoked = FALSE;