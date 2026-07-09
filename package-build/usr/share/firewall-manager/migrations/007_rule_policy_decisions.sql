-- Migration: 007_rule_policy_decisions
-- Description: Server-side rule policy engine audit trail (SEC-003)
-- Tracks auto-approve/flag/reject/admin-approval decisions for each rule or policy set.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policy_decision') THEN
        CREATE TYPE policy_decision AS ENUM ('auto_approved', 'flagged', 'rejected', 'approved_by_admin', 'denied_by_admin');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS rule_policy_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id       UUID REFERENCES firewall_rules(id) ON DELETE SET NULL,
    policy_set_id UUID REFERENCES firewall_policy_sets(id) ON DELETE SET NULL,
    decision      policy_decision NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    reviewer_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rpd_rule ON rule_policy_decisions (rule_id);
CREATE INDEX IF NOT EXISTS idx_rpd_policy ON rule_policy_decisions (policy_set_id);
CREATE INDEX IF NOT EXISTS idx_rpd_decision ON rule_policy_decisions (decision);