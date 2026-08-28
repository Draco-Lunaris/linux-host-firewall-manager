-- Migration: 036_cert_issuer_serial
-- Imported upstream sub-CA support: leaf rows must record WHICH CA issued them
-- (self-root vs imported sub-CA) so CRLs can be grouped per issuing CA — a CRL
-- is only valid when signed by the CA that issued the certs it names.
-- NULL (or the root row's own serial) = issued by the self-generated root.

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS issuer_serial TEXT;