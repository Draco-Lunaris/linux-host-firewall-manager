-- Migration: 016_account_lockout
-- Description: Track failed login attempts and lockout timestamps
-- Forked from LPM 012.

ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;