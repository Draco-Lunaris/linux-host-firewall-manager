-- Migration: 034_policy_set_defaults
-- Description: Per-policy-set default input/output policy (allow/deny/reject).
-- NULL means "system default" — the agent does not call `ufw default` for that
-- direction, preserving the pre-existing reset-based behavior. A non-NULL value
-- is applied as `ufw default <policy> incoming|outgoing`, enabling explicit
-- deny/deny-default policy sets where every flow must be defined explicitly.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'firewall_default_policy') THEN
        CREATE TYPE firewall_default_policy AS ENUM ('allow', 'deny', 'reject');
    END IF;
END $$;

ALTER TABLE firewall_policy_sets
    ADD COLUMN IF NOT EXISTS default_input_policy firewall_default_policy DEFAULT NULL;
ALTER TABLE firewall_policy_sets
    ADD COLUMN IF NOT EXISTS default_output_policy firewall_default_policy DEFAULT NULL;