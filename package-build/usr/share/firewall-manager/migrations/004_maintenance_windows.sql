-- Migration: 004_maintenance_windows
-- Description: Add auto_apply and notification columns to maintenance_windows
-- Forked from LPM 004 + 013.

ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS auto_apply BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS notify_before_minutes INTEGER;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS last_triggered_at TIMESTAMPTZ;