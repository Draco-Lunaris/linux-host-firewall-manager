-- Migration: 013_agent_binary_tracking
-- Description: Track agent binary hash + version for integrity verification (SEC-007)

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_binary_hash TEXT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_min_version TEXT;