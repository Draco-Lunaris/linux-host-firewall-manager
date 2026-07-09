-- Migration: 003_jobs_scheduling
-- Description: Add scheduling columns to firewall_jobs for maintenance window integration
-- Forked from LPM 003.

ALTER TABLE firewall_jobs ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ;
ALTER TABLE firewall_jobs ADD COLUMN IF NOT EXISTS auto_apply BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_firewall_jobs_scheduled ON firewall_jobs (scheduled_for) WHERE status = 'queued';