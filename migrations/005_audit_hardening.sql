-- Migration: 005_audit_hardening
-- Description: Add new audit_action enum values for firewall domain events
-- Forked from LPM 005 (prev_hash already in 001).

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'audit_integrity_verified';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'email_notification_sent';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'firewall_job_completed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'firewall_job_failed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'maintenance_window_reminder';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'rule_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'rule_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'rule_deleted';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_set_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_set_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_assigned';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_unassigned';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'rule_deployed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'rule_rollback';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'drift_detected';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'backend_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'break_glass_used';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'enrollment_token_issued';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'enrollment_token_used';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'enrollment_token_revoked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'host_enrolled';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'ca_intermediate_issued';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'ca_intermediate_revoked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'audit_anchor_mismatch';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'agent_version_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'agent_binary_hash_changed';