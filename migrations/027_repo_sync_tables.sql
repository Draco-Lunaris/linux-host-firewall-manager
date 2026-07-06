-- Migration: 027_repo_sync_tables
-- Description: Tables for GPG-signed apt/dnf repo synchronization (agent self-update)
-- Forked from LPM 028.

CREATE TABLE IF NOT EXISTS repo_sync_state (
    distro_id       TEXT PRIMARY KEY,
    last_synced_at  TIMESTAMPTZ,
    last_sync_status TEXT NOT NULL DEFAULT 'pending',
    packages_synced  INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);

CREATE TABLE IF NOT EXISTS repo_packages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    distro_id       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    architecture     TEXT NOT NULL DEFAULT 'amd64',
    file_path       TEXT NOT NULL,
    checksum        TEXT,
    checksum_type   TEXT NOT NULL DEFAULT 'sha256',
    size_bytes      BIGINT,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (distro_id, package_name, version, architecture)
);
CREATE INDEX IF NOT EXISTS idx_repo_packages_distro ON repo_packages (distro_id);
CREATE INDEX IF NOT EXISTS idx_repo_packages_name ON repo_packages (package_name);