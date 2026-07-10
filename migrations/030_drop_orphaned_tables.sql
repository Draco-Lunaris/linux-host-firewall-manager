-- Migration: 030_drop_orphaned_tables
-- Description: Drop orphaned tables, columns, and enum values from removed features
-- (Repo Management, OS Package Mappings, Agent Upgrade Versions, CRL tracking, GPG)
--
-- Tables dropped:
--   - available_versions (agent self-upgrade version cache — migration 023)
--   - repo_sync_state (package repo sync state — migration 027)
--   - repo_packages (package repo package listing — migration 027)
--
-- Columns dropped from hosts:
--   - agent_binary_hash (migration 013)
--   - agent_min_version (migration 013)
--   - container_runtime (migration 014)
--   - container_override (migration 014)
--   - crl_status (migration 021)
--   - crl_age_seconds (migration 021)
--   - crl_next_update (migration 021)
--
-- Enum values removed from audit_action:
--   - agent_version_changed (migration 022)
--   - agent_binary_hash_changed (migration 022)
--   - crl_status_changed (migration 021)
--   - crl_stale_detected (migration 021)
--   - crl_invalid (migration 021)
--   - upgrade_triggered (migration 024)
--   - batch_upgrade_triggered (migration 024)
--   - upgrade_version_refreshed (migration 024)
--
-- Enum values removed from job_kind:
--   - self_upgrade (migration 023)
--
-- Note: PostgreSQL does not support removing individual ENUM values directly.
-- The standard approach is to recreate the type without the unwanted values.
-- We use a safe approach: create new type, migrate data, swap, drop old.

-- ============================================================
-- Drop orphaned tables
-- ============================================================

DROP TABLE IF EXISTS repo_packages CASCADE;
DROP TABLE IF EXISTS repo_sync_state CASCADE;
DROP TABLE IF EXISTS available_versions CASCADE;

-- ============================================================
-- Drop orphaned columns from hosts
-- ============================================================

ALTER TABLE hosts DROP COLUMN IF EXISTS agent_binary_hash;
ALTER TABLE hosts DROP COLUMN IF EXISTS agent_min_version;
ALTER TABLE hosts DROP COLUMN IF EXISTS container_runtime;
ALTER TABLE hosts DROP COLUMN IF EXISTS container_override;
ALTER TABLE hosts DROP COLUMN IF EXISTS crl_status;
ALTER TABLE hosts DROP COLUMN IF EXISTS crl_age_seconds;
ALTER TABLE hosts DROP COLUMN IF EXISTS crl_next_update;

-- ============================================================
-- Recreate audit_action enum without orphaned values
-- ============================================================

CREATE TYPE audit_action_new AS ENUM (
    'user_login', 'user_logout', 'user_login_failed',
    'user_created', 'user_deleted', 'user_updated',
    'host_registered', 'host_removed',
    'group_created', 'group_deleted', 'group_membership_changed',
    'firewall_job_created', 'firewall_job_cancelled', 'firewall_job_rollback',
    'maintenance_window_created', 'maintenance_window_updated', 'maintenance_window_deleted',
    'certificate_issued', 'certificate_renewed', 'certificate_revoked', 'certificate_downloaded',
    'config_changed', 'discovery_scan_started',
    'audit_integrity_verified', 'email_notification_sent',
    'firewall_job_completed', 'firewall_job_failed',
    'maintenance_window_reminder',
    'rule_created', 'rule_updated', 'rule_deleted',
    'policy_set_created', 'policy_set_changed', 'policy_assigned', 'policy_unassigned',
    'rule_deployed', 'rule_rollback', 'drift_detected', 'backend_changed',
    'break_glass_used',
    'enrollment_token_issued', 'enrollment_token_used', 'enrollment_token_revoked',
    'host_enrolled',
    'ca_intermediate_issued', 'ca_intermediate_revoked',
    'audit_anchor_mismatch'
);

-- Migrate existing audit_log data to the new type
ALTER TABLE audit_log ALTER COLUMN action TYPE audit_action_new USING action::text::audit_action_new;

-- Swap types
DROP TYPE audit_action;
ALTER TYPE audit_action_new RENAME TO audit_action;

-- ============================================================
-- Recreate job_kind enum without self_upgrade
-- ============================================================

CREATE TYPE job_kind_new AS ENUM (
    'rule_apply', 'rule_remove', 'reboot', 'rollback'
);

-- Migrate existing data
ALTER TABLE firewall_jobs ALTER COLUMN kind DROP DEFAULT;
ALTER TABLE firewall_jobs ALTER COLUMN kind TYPE job_kind_new USING kind::text::job_kind_new;
ALTER TABLE firewall_jobs ALTER COLUMN kind SET DEFAULT 'rule_apply'::job_kind_new;

-- Swap types
DROP TYPE job_kind;
ALTER TYPE job_kind_new RENAME TO job_kind;

-- Fix the default to use the renamed type
ALTER TABLE firewall_jobs ALTER COLUMN kind SET DEFAULT 'rule_apply'::job_kind;