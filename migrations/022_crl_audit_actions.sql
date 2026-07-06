-- Migration: 022_crl_audit_actions
-- Description: Add CRL-related audit actions
-- Forked from LPM 022.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_status_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_stale_detected';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'crl_invalid';