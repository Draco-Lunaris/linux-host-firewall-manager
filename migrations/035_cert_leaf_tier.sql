-- Migration: 035_crl_host_certs
-- CRL revocation support: host (leaf) certs must be persisted at issuance so
-- they can be revoked and their serials fed into the CRL. The ca_tier CHECK
-- from migration 012 only allows root/intermediate; extend it with 'leaf'.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'certificates_ca_tier_check'
    ) THEN
        ALTER TABLE certificates DROP CONSTRAINT certificates_ca_tier_check;
    END IF;
END $$;

ALTER TABLE certificates ADD CONSTRAINT certificates_ca_tier_check
    CHECK (ca_tier IN ('root', 'intermediate', 'leaf'));