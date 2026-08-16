-- Migration: 032_enrollment_csr
-- Description: Persist the agent's CSR at enrollment submission so the manager
-- can sign it when the admin approves the enrollment request.

ALTER TABLE enrollment_requests ADD COLUMN IF NOT EXISTS csr TEXT;