-- Migration: 010_operator_host_groups
-- Description: Operator host-group scoping + break-glass role (SEC-012)
-- Operators can only push rules to hosts in their assigned groups.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'user_role' AND e.enumlabel = 'break_glass_operator'
    ) THEN
        ALTER TYPE user_role ADD VALUE 'break_glass_operator';
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS operator_host_groups (
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_ohg_group ON operator_host_groups (group_id);