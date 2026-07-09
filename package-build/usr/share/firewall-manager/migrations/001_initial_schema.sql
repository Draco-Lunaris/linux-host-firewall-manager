-- Migration: 001_initial_schema
-- Description: Full initial schema for Linux Host Firewall Manager
-- Forked from Linux-Patch-Manager 001, adapted for firewall domain.
-- Uses UUID PKs, TIMESTAMPTZ, hash-chained audit log, ENUM types.

-- ============================================================
-- Extensions
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================
-- Enumerations
-- ============================================================

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('admin', 'operator');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auth_provider') THEN
        CREATE TYPE auth_provider AS ENUM ('local', 'azure_sso');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'host_health_status') THEN
        CREATE TYPE host_health_status AS ENUM ('pending', 'healthy', 'degraded', 'unreachable');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_status') THEN
        CREATE TYPE job_status AS ENUM ('queued', 'pending', 'running', 'succeeded', 'failed', 'cancelled');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_kind') THEN
        CREATE TYPE job_kind AS ENUM ('rule_apply', 'rule_remove', 'reboot', 'rollback');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'window_recurrence') THEN
        CREATE TYPE window_recurrence AS ENUM ('once', 'daily', 'weekly', 'monthly');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cert_status') THEN
        CREATE TYPE cert_status AS ENUM ('active', 'revoked', 'expired');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_action') THEN
        CREATE TYPE audit_action AS ENUM (
            'user_login', 'user_logout', 'user_login_failed',
            'user_created', 'user_deleted', 'user_updated',
            'host_registered', 'host_removed',
            'group_created', 'group_deleted',
            'group_membership_changed',
            'firewall_job_created', 'firewall_job_cancelled', 'firewall_job_rollback',
            'maintenance_window_created', 'maintenance_window_updated', 'maintenance_window_deleted',
            'certificate_issued', 'certificate_renewed', 'certificate_revoked', 'certificate_downloaded',
            'config_changed',
            'discovery_scan_started'
        );
    END IF;
END $$;

-- ============================================================
-- Groups
-- ============================================================
CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups (name);

-- ============================================================
-- Users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL DEFAULT '',
    email               TEXT NOT NULL UNIQUE,
    role                user_role NOT NULL DEFAULT 'operator',
    auth_provider       auth_provider NOT NULL DEFAULT 'local',
    password_hash       TEXT,
    totp_secret         TEXT,
    webauthn_credential JSONB,
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    azure_oid           TEXT UNIQUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    force_password_reset BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_azure_oid ON users (azure_oid) WHERE azure_oid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

-- ============================================================
-- User <-> Group membership
-- ============================================================
CREATE TABLE IF NOT EXISTS user_groups (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups (group_id);

-- ============================================================
-- Refresh Tokens
-- ============================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    user_agent      TEXT,
    ip_address      INET
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens (expires_at) WHERE revoked = FALSE;

-- ============================================================
-- Hosts
-- ============================================================
CREATE TABLE IF NOT EXISTS hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fqdn            TEXT NOT NULL,
    ip_address      INET NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    os_family       TEXT,
    os_name         TEXT,
    arch            TEXT,
    agent_version   TEXT,
    health_status   host_health_status NOT NULL DEFAULT 'pending',
    last_health_at  TIMESTAMPTZ,
    last_sync_at    TIMESTAMPTZ,
    agent_port      INTEGER NOT NULL DEFAULT 12443,
    notes           TEXT NOT NULL DEFAULT '',
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT hosts_fqdn_ip_unique UNIQUE (fqdn, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_hosts_health_status ON hosts (health_status);
CREATE INDEX IF NOT EXISTS idx_hosts_fqdn ON hosts USING gin (fqdn gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip_address);

-- ============================================================
-- Host <-> Group membership
-- ============================================================
CREATE TABLE IF NOT EXISTS host_groups (
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_host_groups_group ON host_groups (group_id);

-- ============================================================
-- Host Health Data (cached results from 5-min polls)
-- ============================================================
CREATE TABLE IF NOT EXISTS host_health_data (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    polled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status      host_health_status NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_host_health_host ON host_health_data (host_id, polled_at DESC);

-- ============================================================
-- Firewall Rule Enums
-- ============================================================
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'firewall_action') THEN
        CREATE TYPE firewall_action AS ENUM ('allow', 'deny', 'reject', 'limit', 'masquerade');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'firewall_direction') THEN
        CREATE TYPE firewall_direction AS ENUM ('in', 'out', 'forward');
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'firewall_protocol') THEN
        CREATE TYPE firewall_protocol AS ENUM ('any', 'tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah', 'sctp');
    END IF;
END $$;

-- ============================================================
-- Firewall Rules (typed, validated — no shell content)
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    action          firewall_action NOT NULL,
    direction       firewall_direction NOT NULL DEFAULT 'in',
    protocol        firewall_protocol NOT NULL DEFAULT 'any',
    src_cidr        INET,
    src_port_start  INTEGER CHECK (src_port_start IS NULL OR (src_port_start BETWEEN 1 AND 65535)),
    src_port_end    INTEGER CHECK (src_port_end IS NULL OR (src_port_end BETWEEN 1 AND 65535)),
    dst_cidr        INET,
    dst_port_start  INTEGER CHECK (dst_port_start IS NULL OR (dst_port_start BETWEEN 1 AND 65535)),
    dst_port_end    INTEGER CHECK (dst_port_end IS NULL OR (dst_port_end BETWEEN 1 AND 65535)),
    interface_in    TEXT,
    interface_out   TEXT,
    comment         TEXT NOT NULL DEFAULT '',
    log             BOOLEAN NOT NULL DEFAULT FALSE,
    priority        INTEGER NOT NULL DEFAULT 1000,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (src_port_start IS NULL AND src_port_end IS NULL) OR
        (src_port_start IS NOT NULL AND src_port_end IS NOT NULL AND src_port_start <= src_port_end)
    ),
    CHECK (
        (dst_port_start IS NULL AND dst_port_end IS NULL) OR
        (dst_port_start IS NOT NULL AND dst_port_end IS NOT NULL AND dst_port_start <= dst_port_end)
    )
);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_name ON firewall_rules (name);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_action ON firewall_rules (action);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules (priority);

-- ============================================================
-- Firewall Policy Sets (named bundles of rules — replaces "roles")
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_policy_sets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_firewall_policy_sets_name ON firewall_policy_sets (name);

-- ============================================================
-- Firewall Policy Set Rules (many-to-many with ordering)
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_policy_set_rules (
    policy_set_id UUID NOT NULL REFERENCES firewall_policy_sets(id) ON DELETE CASCADE,
    rule_id       UUID NOT NULL REFERENCES firewall_rules(id) ON DELETE RESTRICT,
    rule_order    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_set_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_fpsr_order ON firewall_policy_set_rules (policy_set_id, rule_order);

-- ============================================================
-- Host Policy Assignments (replaces /etc/fw/role.env)
-- ============================================================
CREATE TABLE IF NOT EXISTS host_policy_assignments (
    host_id        UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    policy_set_id  UUID NOT NULL REFERENCES firewall_policy_sets(id) ON DELETE CASCADE,
    assigned_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, policy_set_id)
);
CREATE INDEX IF NOT EXISTS idx_hpa_policy ON host_policy_assignments (policy_set_id);

-- ============================================================
-- Drift Snapshots (per-host rule snapshots for drift detection)
-- ============================================================
CREATE TABLE IF NOT EXISTS drift_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot_hash   TEXT NOT NULL,
    rule_count       INTEGER NOT NULL DEFAULT 0,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          TEXT NOT NULL DEFAULT 'job_result'
);
CREATE INDEX IF NOT EXISTS idx_drift_host ON drift_snapshots (host_id, captured_at DESC);

-- ============================================================
-- Maintenance Windows
-- ============================================================
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    label           TEXT NOT NULL DEFAULT '',
    recurrence      window_recurrence NOT NULL DEFAULT 'once',
    start_at        TIMESTAMPTZ NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    recurrence_day  INTEGER,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mw_host ON maintenance_windows (host_id);
CREATE INDEX IF NOT EXISTS idx_mw_start ON maintenance_windows (start_at) WHERE enabled = TRUE;

-- ============================================================
-- Firewall Jobs
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                job_kind NOT NULL DEFAULT 'rule_apply',
    status              job_status NOT NULL DEFAULT 'queued',
    created_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    parent_job_id       UUID REFERENCES firewall_jobs(id) ON DELETE SET NULL,
    maintenance_window_id UUID REFERENCES maintenance_windows(id) ON DELETE SET NULL,
    immediate           BOOLEAN NOT NULL DEFAULT FALSE,
    policy_set_id       UUID REFERENCES firewall_policy_sets(id),
    notes               TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_firewall_jobs_status ON firewall_jobs (status);
CREATE INDEX IF NOT EXISTS idx_firewall_jobs_created ON firewall_jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_firewall_jobs_user ON firewall_jobs (created_by_user_id);

-- ============================================================
-- Firewall Job Hosts (per-host status within a batch job)
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_job_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES firewall_jobs(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          job_status NOT NULL DEFAULT 'queued',
    agent_job_id    TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    output          TEXT NOT NULL DEFAULT '',
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    UNIQUE (job_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_fjh_job ON firewall_job_hosts (job_id);
CREATE INDEX IF NOT EXISTS idx_fjh_host ON firewall_job_hosts (host_id);
CREATE INDEX IF NOT EXISTS idx_fjh_status ON firewall_job_hosts (status);

-- ============================================================
-- Certificates
-- ============================================================
CREATE TABLE IF NOT EXISTS certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    serial_number   TEXT NOT NULL UNIQUE,
    common_name     TEXT NOT NULL,
    status          cert_status NOT NULL DEFAULT 'active',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    cert_pem        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_host ON certificates (host_id);
CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certs_expires ON certificates (expires_at);

-- ============================================================
-- Audit Log (tamper-evident, hash-chained)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    action          audit_action NOT NULL,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_username  TEXT,
    target_type     TEXT,
    target_id       TEXT,
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      INET,
    request_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    row_hash        TEXT NOT NULL DEFAULT '',
    prev_hash       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log (target_type, target_id);

-- ============================================================
-- Azure SSO Configuration
-- ============================================================
CREATE TABLE IF NOT EXISTS azure_sso_config (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_id       TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL DEFAULT '',
    client_secret   TEXT NOT NULL DEFAULT '',
    redirect_uri    TEXT NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL DEFAULT 'openid email profile',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT azure_sso_singleton CHECK (id = 1)
);

-- ============================================================
-- System Configuration (key/value runtime settings)
-- ============================================================
CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_config (key, value, description) VALUES
    ('health_poll_interval_secs',  '300',   'Agent health check interval in seconds'),
    ('drift_poll_interval_secs',    '900',   'Agent drift check interval in seconds'),
    ('max_concurrent_agent_calls',  '64',    'Maximum concurrent mTLS agent calls'),
    ('data_retention_days',         '30',    'Retention period for operational data (days)'),
    ('audit_retention_days',        '180',   'Retention period for audit log (days)'),
    ('smtp_enabled',                'false', 'Enable email notifications'),
    ('smtp_host',                   '',      'SMTP relay hostname'),
    ('smtp_port',                   '587',   'SMTP relay port'),
    ('smtp_username',               '',      'SMTP auth username'),
    ('smtp_password',               '',      'SMTP auth password'),
    ('smtp_from',                   '',      'From address for notifications'),
    ('smtp_tls_mode',               'starttls', 'SMTP TLS mode: none, starttls, tls'),
    ('web_tls_strategy',            'internal_ca', 'Web UI TLS cert strategy: internal_ca or operator_supplied'),
    ('ip_whitelist',                '[]',    'JSON array of allowed CIDR/IP strings; empty = allow all'),
    ('audit_integrity_last_verified', '', 'Last verified audit chain head hash')
ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- Worker Heartbeat
-- ============================================================
CREATE TABLE IF NOT EXISTS worker_heartbeat (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    worker_version  TEXT NOT NULL DEFAULT '',
    CONSTRAINT worker_heartbeat_singleton CHECK (id = 1)
);

-- ============================================================
-- Discovery Results
-- ============================================================
CREATE TABLE IF NOT EXISTS discovery_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL,
    ip_address      INET NOT NULL,
    fqdn            TEXT,
    agent_version   TEXT,
    os_name         TEXT,
    agent_port      INTEGER NOT NULL DEFAULT 12443,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered      BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_discovery_scan ON discovery_results (scan_id);
CREATE INDEX IF NOT EXISTS idx_discovery_ip ON discovery_results (ip_address);