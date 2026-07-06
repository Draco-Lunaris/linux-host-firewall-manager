-- Migration: 012_ca_tier
-- Description: Two-tier CA model — offline root + online intermediate (SEC-001)
-- Distinguish root vs intermediate certs and track parentage.

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS ca_tier TEXT NOT NULL DEFAULT 'intermediate'
    CHECK (ca_tier IN ('root', 'intermediate'));
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS parent_cert_id UUID REFERENCES certificates(id);

-- The root CA cert is inserted by the CA init process, not by migration.
-- Mark it as 'root' tier with no parent.