-- Migration: 024_upgrade_audit_actions
-- Description: Add upgrade-related audit actions
-- Forked from LPM 024.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'upgrade_triggered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'batch_upgrade_triggered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'upgrade_version_refreshed';