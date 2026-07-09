-- Migration: 026_prevent_duplicate_auto_jobs
-- Description: Prevent duplicate auto-apply jobs for the same host/window
-- Forked from LPM 027.

-- Add a unique partial index: only one queued/pending auto-apply job per host per window
CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_jobs_auto_unique
    ON firewall_jobs (maintenance_window_id, kind)
    WHERE status IN ('queued', 'pending') AND auto_apply = TRUE;