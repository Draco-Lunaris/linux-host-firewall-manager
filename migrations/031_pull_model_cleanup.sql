-- Migration: 031_pull_model_cleanup
-- Description: Drop the job/maintenance machinery for the agent-pull model and add
-- apply-history columns for the no-jobs assign-and-apply lifecycle.
--
-- The pull model has no job queue, no maintenance windows, and no per-host push
-- serialization lock on the manager (serialization is the agent's responsibility).
-- Apply results are recorded on agent_check_ins instead of firewall_job_hosts.
--
-- Tables dropped:
--   - firewall_job_hosts (migration 001)
--   - firewall_jobs (migration 001 / 003)
--   - maintenance_windows (migration 004)
--   - host_apply_locks (migration 015 — manager-side push serialization, unused in pull)
--   - host_health_data (migration 001 — cached poll results; stale detector uses agent_check_ins)
--
-- Types dropped (unreferenced after the table drops):
--   - job_kind, job_status, window_recurrence
--
-- Columns added:
--   - agent_check_ins.apply_success / apply_error / applied_rule_count / applied_at
--     (written by the check-in/result endpoint; NULL until a result arrives)
--   - host_config_overrides.last_known_good_hash (agent safe-mode revert target)
--
-- Enum value added:
--   - audit_action.policy_force_checkin (the "force check-in now" signal)
--
-- NOTE: pending_action_type 'agent_upgrade', pending_action_status 'pushing', and
-- host_config_overrides.push_enabled remain for now (cross-cutting agent+manager
-- removal is handled alongside the agent push-server deletion). The job/maintenance
-- audit_action variants are retained to avoid rewriting existing audit rows; no new
-- code logs them.

-- ============================================================
-- Drop job / maintenance / push-serialization tables
-- ============================================================

DROP TABLE IF EXISTS firewall_job_hosts CASCADE;
DROP TABLE IF EXISTS firewall_jobs CASCADE;
DROP TABLE IF EXISTS maintenance_windows CASCADE;
DROP TABLE IF EXISTS host_apply_locks CASCADE;
DROP TABLE IF EXISTS host_health_data CASCADE;

-- ============================================================
-- Drop now-unreferenced enum types
-- ============================================================

DROP TYPE IF EXISTS job_kind;
DROP TYPE IF EXISTS job_status;
DROP TYPE IF EXISTS window_recurrence;

-- ============================================================
-- Apply-history columns on agent_check_ins
-- ============================================================

ALTER TABLE agent_check_ins ADD COLUMN IF NOT EXISTS apply_success BOOLEAN;
ALTER TABLE agent_check_ins ADD COLUMN IF NOT EXISTS apply_error TEXT;
ALTER TABLE agent_check_ins ADD COLUMN IF NOT EXISTS applied_rule_count INTEGER;
ALTER TABLE agent_check_ins ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ;

-- ============================================================
-- Safe-mode revert target on host_config_overrides
-- ============================================================

ALTER TABLE host_config_overrides ADD COLUMN IF NOT EXISTS last_known_good_hash TEXT;

-- ============================================================
-- New audit action: force-check-in signal
-- ============================================================

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_force_checkin';