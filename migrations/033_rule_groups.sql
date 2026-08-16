-- Migration: 033_rule_groups
-- Description: Introduce rule groups — the missing middle tier of the four-tier
-- containment model (Rules -> Rule Groups -> Policy Sets -> Hosts).
--
-- Previously individual rules attached directly to a policy set via
-- firewall_policy_set_rules, so rules were added to sets one at a time and a
-- reusable bundle of rules ("everything to talk to linux-patch-manager") could
-- not be changed in one place and propagated. A rule group is now the reusable,
-- ordered unit: a rule belongs to exactly one group (1:1, FK on the rule), and
-- a policy set collects an ordered list of rule groups. Editing a rule in a
-- group propagates to every policy set that includes that group on the agent's
-- next check-in. The manager flattens groups->rules when serving the agent, so
-- the agent and the drift hash are unchanged by this.
--
-- New tables:
--   firewall_rule_groups
--   firewall_policy_set_rule_groups   (M:N groups <-> sets, ordered in the set)
--
-- Columns added:
--   firewall_rules.rule_group_id  UUID NOT NULL -> firewall_rule_groups(id) CASCADE
--   firewall_rules.group_order    INT  (order within the group)
--
-- Dropped (after data migration):
--   firewall_policy_set_rules (+ idx_fpsr_order) — the old direct rule->set join

CREATE TABLE IF NOT EXISTS firewall_rule_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A rule's group home (nullable first; migrated below, then NOT NULL). Deleting
-- a group cascades its rules (1:1 ownership).
ALTER TABLE firewall_rules ADD COLUMN rule_group_id UUID REFERENCES firewall_rule_groups(id) ON DELETE CASCADE;
ALTER TABLE firewall_rules ADD COLUMN group_order INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_rules_group_order ON firewall_rules (rule_group_id, group_order);

-- M:N: a policy set collects an ordered list of rule groups. RESTRICT on the
-- group side so deleting a group that's still in use fails (the API returns 409).
CREATE TABLE IF NOT EXISTS firewall_policy_set_rule_groups (
    policy_set_id   UUID NOT NULL REFERENCES firewall_policy_sets(id) ON DELETE CASCADE,
    rule_group_id   UUID NOT NULL REFERENCES firewall_rule_groups(id) ON DELETE RESTRICT,
    set_group_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_set_id, rule_group_id)
);
CREATE INDEX IF NOT EXISTS idx_fpsrg_order ON firewall_policy_set_rule_groups (policy_set_id, set_group_order);

-- Migrate existing direct rule->set attachments into one auto group per policy
-- set, preserving each set's effective rule list and order. A rule shared across
-- multiple sets (an artifact of the old M:N join) is duplicated for the 2nd+ set
-- so each group is self-contained — rules are 1:1 with their group now. Rules
-- not attached to any set go to a catch-all "Unassigned" group. Un-shared rules
-- keep their original id, so their drift hash is unchanged (no needless re-apply).
DO $$
DECLARE
    ps RECORD;
    g  UUID;
    ug UUID;
    r  RECORD;
    n  INT;
BEGIN
    SELECT count(*) INTO n FROM firewall_rules fr
    WHERE NOT EXISTS (SELECT 1 FROM firewall_policy_set_rules psr WHERE psr.rule_id = fr.id);
    IF n > 0 THEN
        INSERT INTO firewall_rule_groups (name, description)
        VALUES ('Unassigned rules (auto)', 'Rules with no policy set at migration')
        RETURNING id INTO ug;
    END IF;

    FOR ps IN SELECT id, name FROM firewall_policy_sets ORDER BY created_at LOOP
        IF NOT EXISTS (SELECT 1 FROM firewall_policy_set_rules WHERE policy_set_id = ps.id) THEN
            CONTINUE;
        END IF;

        INSERT INTO firewall_rule_groups (name, description)
        VALUES (ps.name || ' (auto)', 'Migrated from direct policy-set rules')
        RETURNING id INTO g;

        FOR r IN SELECT rule_id, rule_order
                 FROM firewall_policy_set_rules
                 WHERE policy_set_id = ps.id
                 ORDER BY rule_order LOOP
            IF EXISTS (SELECT 1 FROM firewall_rules WHERE id = r.rule_id AND rule_group_id IS NULL) THEN
                -- first set to use this rule claims it (keeps its id + hash)
                UPDATE firewall_rules
                SET rule_group_id = g, group_order = r.rule_order
                WHERE id = r.rule_id;
            ELSE
                -- already claimed by another set's group: duplicate into this one.
                -- The name column is UNIQUE, so the copy gets a unique suffix
                -- (a shared rule across N sets yields N-1 uniquely-named copies).
                INSERT INTO firewall_rules (
                    id, name, description, action, direction, protocol,
                    src_cidr, src_port_start, src_port_end, dst_cidr, dst_port_start, dst_port_end,
                    interface_in, interface_out, comment, log, priority, created_by, created_at, updated_at,
                    rule_group_id, group_order
                )
                SELECT
                    gen_random_uuid(),
                    name || ' (copy ' || substr(gen_random_uuid()::text, 1, 8) || ')',
                    description, action, direction, protocol,
                    src_cidr, src_port_start, src_port_end, dst_cidr, dst_port_start, dst_port_end,
                    interface_in, interface_out, comment, log, priority, created_by, created_at, updated_at,
                    g, r.rule_order
                FROM firewall_rules WHERE id = r.rule_id;
            END IF;
        END LOOP;

        INSERT INTO firewall_policy_set_rule_groups (policy_set_id, rule_group_id, set_group_order)
        VALUES (ps.id, g, 0);
    END LOOP;

    IF n > 0 THEN
        UPDATE firewall_rules SET rule_group_id = ug WHERE rule_group_id IS NULL;
    END IF;

    ALTER TABLE firewall_rules ALTER COLUMN rule_group_id SET NOT NULL;
END $$;

DROP TABLE IF EXISTS firewall_policy_set_rules;