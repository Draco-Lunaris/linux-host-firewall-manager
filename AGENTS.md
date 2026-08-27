# AGENTS.md — Conventions for AI Agents

## Communication model (agent-pull)
- **Agent-pull / check-in only.** Agents poll the manager and pull their assigned policy; the
  manager **never** initiates contact with agents. There is no push/deploy path and no
  manager-to-agent HTTP client. (This departs from LPM's manager-push architecture — only LPM's
  look-and-feel is mirrored, not its communication model.)
- Apply lifecycle is **assign & apply**: an admin assigns a policy set to a host/group; the agent
  pulls and applies it on its next check-in (default ~15 min). There is no jobs or
  maintenance-windows machinery. A pull-compatible "force check-in now" is delivered over an
  agent-held SSE subscription (`GET /api/v1/agent/events`); the manager signals via an in-memory
  `Notify`, never by opening a connection to the agent.
- Host identity is bound by mTLS: the manager signs each agent's CSR with `CN=<host_id>` and
  enforces client-cert verification on the dedicated agent listener. The cert *is* the identity;
  `host_id` is never trusted from a request body.

## Agent self-update
- **Out of scope for the current cleanup.** The previous "manager pulls from GitHub Releases,
  signs a GPG-signed apt/dnf repo on port 80, agent self-updates" rule was LPM leftover and is
  **removed**. A new agent update method will be designed separately. Until then, agents are
  updated out-of-band by the operator (manual `apt`/`dnf`). Do not re-introduce the GPG-apt-repo
  path or any manager→agent push of upgrade commands.

## Follow-ups (out of scope for the pull-model cleanup)
1. Agent self-update mechanism — new design to replace the obsolete GPG-apt-repo rule.
2. Atomic UFW apply via `iptables-save` / `iptables-restore` (replaces the current
   `ufw reset` + replay, which has a brief rules-cleared window).
3. Real external audit anchoring (S3 Object Lock / RFC 3161 TSA) — the worker records anchors
   but does not yet verify them against an external store.
4. Containerized integration tests (Ubuntu/UFW + Alma/firewalld) for the agent backends.

## Migrations
- Migrations are SQL files in `migrations/`, numbered `NNN_description.sql`.
- **Never** `INSERT INTO` a PostgreSQL ENUM TYPE — use `ALTER TYPE ... ADD VALUE IF NOT EXISTS`.
- The web process runs migrations under `pg_advisory_lock` at startup.
- The worker waits for a minimum migration count before accepting work.

## Security
- mTLS for all agent communication (TLS 1.3, pinned internal CA, CRL for revocation).
- EdDSA JWT (Ed25519, 15-min TTL), Argon2id passwords, TOTP MFA, AES-256-GCM secrets at rest.
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