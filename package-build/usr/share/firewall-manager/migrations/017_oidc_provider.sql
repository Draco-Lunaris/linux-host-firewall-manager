-- Migration: 017_oidc_provider
-- Description: Generic OIDC provider support (Keycloak, Azure AD, custom)
-- Forked from LPM 014.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON e.enumtypid = t.oid WHERE t.typname = 'auth_provider' AND e.enumlabel = 'keycloak') THEN
        ALTER TYPE auth_provider ADD VALUE 'keycloak';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON e.enumtypid = t.oid WHERE t.typname = 'auth_provider' AND e.enumlabel = 'oidc') THEN
        ALTER TYPE auth_provider ADD VALUE 'oidc';
    END IF;
END
$$;

ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub TEXT;
CREATE INDEX IF NOT EXISTS idx_users_oidc_sub ON users (oidc_sub) WHERE oidc_sub IS NOT NULL;

CREATE TABLE IF NOT EXISTS oidc_config (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    provider_type   TEXT NOT NULL DEFAULT 'azure' CHECK (provider_type IN ('keycloak', 'azure', 'custom')),
    display_name    TEXT NOT NULL DEFAULT 'Azure AD',
    discovery_url   TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL DEFAULT '',
    client_secret   TEXT NOT NULL DEFAULT '',
    redirect_uri    TEXT NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL DEFAULT 'openid profile email',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO oidc_config (enabled, provider_type, display_name)
SELECT FALSE, 'azure', 'Azure AD'
WHERE NOT EXISTS (SELECT 1 FROM oidc_config WHERE id = 1);