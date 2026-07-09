-- Migration: 021_crl_health_status
-- Description: Add CRL health status columns to hosts table
-- Forked from LPM 021.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_status TEXT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_age_seconds BIGINT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS crl_next_update TIMESTAMPTZ;