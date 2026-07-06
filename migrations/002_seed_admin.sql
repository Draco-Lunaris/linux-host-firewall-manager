-- Migration: 002_seed_admin
-- Description: Seed default admin user with placeholder password hash
-- The bootstrap_admin_password function in fw-web replaces this on first start.

INSERT INTO users (username, display_name, email, role, password_hash, mfa_enabled, is_active, force_password_reset)
VALUES ('admin', 'Administrator', 'admin@localhost', 'admin',
        'PLACEHOLDER_HASH', FALSE, TRUE, TRUE)
ON CONFLICT (username) DO NOTHING;