-- Migration: 029_pending_actions
-- Description: Queued push actions for the hybrid push/pull model.
-- High-priority actions are pushed via mTLS; if push fails they fall back to pull delivery.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'pending_action_type') THEN
        CREATE TYPE pending_action_type AS ENUM (
            'apply_rules', 'rollback', 'safe_mode_on', 'safe_mode_off',
            'reload_config', 'agent_upgrade'
        );
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'pending_action_status') THEN
        CREATE TYPE pending_action_status AS ENUM (
            'queued', 'pushing', 'delivered', 'executed', 'failed', 'expired'
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS pending_actions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id          UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    action_type      pending_action_type NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}',
    reason           TEXT NOT NULL DEFAULT '',
    priority         INTEGER NOT NULL DEFAULT 0,
    status           pending_action_status NOT NULL DEFAULT 'queued',
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL DEFAULT 3,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_attempt_at TIMESTAMPTZ,
    delivered_at     TIMESTAMPTZ,
    executed_at      TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);

CREATE INDEX idx_pending_host_status ON pending_actions (host_id, status);
CREATE INDEX idx_pending_priority ON pending_actions (priority, created_at);