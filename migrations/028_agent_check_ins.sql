-- Migration: 028_agent_check_ins
-- Description: Agent check-in records and per-host config overrides for the pull model.

CREATE TABLE IF NOT EXISTS agent_check_ins (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rules_hash      TEXT NOT NULL DEFAULT '',
    agent_version   TEXT NOT NULL DEFAULT '',
    backend_type    TEXT NOT NULL DEFAULT '',
    os_info         JSONB NOT NULL DEFAULT '{}',
    uptime_seconds  BIGINT NOT NULL DEFAULT 0,
    config_version  INTEGER NOT NULL DEFAULT 0,
    pending_results JSONB NOT NULL DEFAULT '[]',
    checked_in_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_checkins_host_time ON agent_check_ins (host_id, checked_in_at DESC);

CREATE TABLE IF NOT EXISTS host_config_overrides (
    host_id                 UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    check_in_interval_secs  INTEGER NOT NULL DEFAULT 900,
    push_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    safe_mode_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    backend_override        TEXT,
    config_version          INTEGER NOT NULL DEFAULT 1,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);