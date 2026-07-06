# AGENTS.md — Conventions for AI Agents

## Build model
- **Manager Pull model only.** Never implement a CI push model for agent updates.
- The manager pulls packages from GitHub Releases, signs them with a per-manager GPG key, and serves them via a GPG-signed apt/dnf repo on port 80 (plain HTTP — integrity comes from GPG, not TLS).
- The agent self-updates via the standard package update endpoint.

## Migrations
- Migrations are SQL files in `migrations/`, numbered `NNN_description.sql`.
- **Never** `INSERT INTO` a PostgreSQL ENUM TYPE — use `ALTER TYPE ... ADD VALUE IF NOT EXISTS`.
- The web process runs migrations under `pg_advisory_lock` at startup.
- The worker waits for a minimum migration count before accepting work.

## Security
- mTLS for all agent communication (TLS 1.3, pinned internal CA, CRL for revocation).
- Ed25519 JWT (15-min TTL), Argon2id passwords, TOTP MFA, AES-256-GCM secrets at rest.
- Hash-chained audit log with external anchoring (S3 Object Lock / RFC 3161 TSA).
- No shell execution of operator-supplied content — firewall rules are typed DB rows compiled by the agent.
- Per-host authorization: every agent API call is bound to the mTLS-certified host identity.

## Commit conventions
- Conventional commits: `feat:`, `fix:`, `style:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Branch naming: `feat/description`, `fix/description`, `refactor/description`.

## Lessons learned
1. PostgreSQL ENUM types need `ALTER TYPE ... ADD VALUE IF NOT EXISTS`, not `INSERT INTO`.
2. Lettre requires `default-features = false` with `tokio1-rustls-tls` to avoid native-tls conflict.
3. `sqlx::migrate!()` returns `MigrateError`, not `sqlx::Error` — match the return type.
4. `IpNet::is_ipv4()` doesn't exist — use `net.network().is_ipv4()`.
5. `cc` must be in PATH for Rust build scripts even for pure-Rust crates.