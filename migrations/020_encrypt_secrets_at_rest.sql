-- Migration: 020_encrypt_secrets_at_rest
-- Description: Encrypt sensitive secrets at rest with AES-256-GCM (SEC-010)
-- Forked from LPM 020.
-- Hard cutover: operator runs migrate-secrets binary before applying this migration.

-- 1. oidc_config: client_secret
ALTER TABLE oidc_config
    ADD COLUMN IF NOT EXISTS client_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS client_secret_nonce BYTEA;
ALTER TABLE oidc_config
    DROP COLUMN IF EXISTS client_secret;

-- 2. system_config: smtp_password (key-value store)
DELETE FROM system_config WHERE key = 'smtp_password';

-- 3. users: totp_secret
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS totp_secret_nonce BYTEA;
ALTER TABLE users
    DROP COLUMN IF EXISTS totp_secret;