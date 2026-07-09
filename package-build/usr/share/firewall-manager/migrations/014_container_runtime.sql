-- Migration: 014_container_runtime
-- Description: Track container runtime on hosts (SEC-005)
-- Agent detects Docker/Podman/K8s and reports it; UFW backend is refused if present.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS container_runtime TEXT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS container_override BOOLEAN NOT NULL DEFAULT FALSE;