-- Migration: 037_crl_counter
-- Monotonic CRL number counter, one row per issuing CA.
--
-- RFC 5280 §5.2.3 requires the CRL number to be a monotonically increasing
-- serial number. The previous scheme used a wall-clock unix timestamp, which
-- collides when two CRLs are generated in the same second (and can even go
-- backwards if NTP steps the clock). The number is now drawn from a persistent,
-- atomically-incremented counter instead.
CREATE TABLE IF NOT EXISTS crl_counter (
    issuer_key  TEXT PRIMARY KEY,
    last_number BIGINT NOT NULL DEFAULT 0
);
