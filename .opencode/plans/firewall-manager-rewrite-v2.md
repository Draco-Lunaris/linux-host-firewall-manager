# Linux Host Firewall Manager — Rewrite Plan v2 (Approved)

Status: APPROVED 2026-07-06
Scope: v0.1 — UFW + firewalld backends; nftables + iptables deferred to v0.2
Timeline: ~25 days, one engineer

## Confirmed decisions

| Decision | Choice |
|---|---|
| Firewall backends (v0.1) | UFW + firewalld (nftables + iptables deferred to v0.2) |
| Rule model | Structured DB-backed typed rules (no shell chunks, no operator shell content) |
| Agent model | New per-host Rust agent, mTLS (mirror linux_patch_api) |
| Repo structure | Monorepo — manager + agent crates in one workspace |
| Enrollment | CSR-based with one-time per-host token (improvement on LPM's server-generated keys) |
| CA architecture | Offline root CA + online intermediate (root key on air-gapped/KMS, intermediate on manager) |
| Audit anchoring | Externally anchored (S3 Object Lock / RFC 3161 TSA / remote log host) |
| Atomicity (UFW) | iptables-save + iptables-restore (atomic swap, no reset window) |
| Atomicity (firewalld) | --permanent + --reload |
| Migration | Greenfield (no migration from old bash system) |

## Guiding principles

1. Mirror, don't invent — copy Linux-Patch-Manager architecture, crate boundaries, security crate, frontend shell, build/packaging, CI verbatim where the firewall domain allows.
2. Eliminate the validator attack surface — typed rules compiled by agent, no shell execution of operator content.
3. Close old system gaps by construction — mTLS + per-host identity, GPG-signed agent repo, hash-chained + externally-anchored audit log, structured rules signed by DB, real-time drift detection.
4. Reuse code aggressively — pm-auth, pm-ca, pm-core (error/crypto/audit/config/db), pm-web router shell, frontend shell, build/packaging, CI. ~60-70% of LPM reusable.
5. Operator experience first — every CLI has --help, status, --dry-run; UI has rule editor with dropdowns, fleet dashboard, real-time job progress, drift alerts.

## Repository layout (monorepo)

linux-host-firewall-manager/
├── Cargo.toml                      # workspace root (8 members)
├── ARCHITECTURE.md                  # SDD (fork from LPM, adapt to firewall)
├── SPEC.md
├── REQUIREMENTS.md
├── INTERFACE_CONTRACT.md            # manager↔agent contract
├── SECURITY.md
├── AGENTS.md                        # AI agent conventions (fork from LPM)
├── README.md
├── LICENSE                          # Apache-2.0
├── .github/workflows/ci.yml        # mirror LPM CI
├── .gitea/workflows/ci.yml
├── .gitleaks.toml
├── clippy.toml
├── rustfmt.toml
├── Dockerfile                       # multi-stage
├── docker-compose.yml
├── config/config.example.toml       # forked from LPM + [firewall] section
├── crates/
│   ├── fw-web/                      # Axum manager (fork from pm-web)
│   ├── fw-worker/                   # background worker (fork from pm-worker)
│   ├── fw-core/                     # domain models, DB, crypto, audit, config, policy engine
│   ├── fw-auth/                     # JWT, Argon2, TOTP, RBAC, sessions, jti revocation (fork from pm-auth)
│   ├── fw-ca/                       # internal CA: intermediate on manager, root offline (fork from pm-ca)
│   ├── fw-agent-client/             # mTLS client to per-host agents (fork from pm-agent-client)
│   ├── fw-reports/                  # CSV/PDF reporting (fork from pm-reports)
│   ├── fw-agent/                    # NEW — per-host daemon (analogous to linux_patch_api)
│   └── migrate-secrets/             # one-shot AES migration tool (reuse pattern)
├── debian/                          # packaging (rename from LPM)
├── systemd/                         # service units (rename)
├── migrations/
│   ├── 001_initial_schema.sql       # fork from LPM 001, rename patch_* → firewall_*
│   ├── 002_seed_admin.sql            # reuse
│   ├── 003_jobs_scheduling.sql       # reuse
│   ├── 004_maintenance_windows.sql   # reuse
│   ├── 005_audit_hardening.sql       # reuse (hash chain)
│   ├── 006_firewall_rules.sql        # NEW — typed rule table
│   ├── 007_firewall_zones.sql        # NEW — zones/services for firewalld
│   ├── 008_firewall_policy_sets.sql  # NEW — named rule bundles
│   ├── 009_host_rule_assignments.sql # NEW — host ↔ policy_set mapping
│   ├── 010_drift_snapshots.sql       # NEW — per-host rule snapshots
│   ├── 011_protected_cidrs.sql       # NEW (SEC-006) — mgmt-lockout protection
│   ├── 012_rule_policy_decisions.sql # NEW (SEC-003) — rule policy engine audit
│   ├── 013_enrollment_tokens.sql     # NEW (SEC-002) — one-time per-host tokens
│   ├── 014_jti_sessions.sql          # NEW (SEC-011) — JWT revocation
│   ├── 015_operator_host_groups.sql  # NEW (SEC-012) — Operator scoping
│   ├── 016_audit_external_anchor.sql # NEW (SEC-004) — external audit anchor
│   ├── 017_ca_tier.sql               # NEW (SEC-001) — root/intermediate CA tiers
│   ├── 018_agent_binary_tracking.sql # NEW (SEC-007) — agent hash + version
│   ├── 019_container_runtime.sql     # NEW (SEC-005) — container detection
│   ├── 020_per_host_lock.sql         # NEW (SEC-013) — per-host push serialization
│   ├── 021_account_lockout.sql       # reuse verbatim
│   ├── 022_oidc_provider.sql         # reuse verbatim
│   ├── 023_reporter_role.sql         # reuse verbatim
│   ├── 024-026_enrollment_*.sql      # reuse verbatim
│   ├── 027_auth_config_audit.sql     # reuse + extend
│   ├── 028_encrypt_secrets_at_rest.sql # reuse verbatim
│   ├── 029_crl_health_status.sql    # reuse verbatim
│   ├── 030_crl_audit_actions.sql     # reuse verbatim
│   ├── 031_self_upgrade.sql         # reuse verbatim
│   ├── 032_upgrade_audit_actions.sql # reuse + extend
│   ├── 033_firewall_backend_mappings.sql # NEW — OS → preferred backend
│   ├── 034_prevent_duplicate_auto_jobs.sql # reuse
│   └── 035_repo_sync_tables.sql      # reuse (for agent self-update repo)
├── docs/
│   ├── REST_API.md
│   ├── security-review.md
│   ├── ca-compromise-runbook.md      # NEW (SEC-009) — CA compromise response
│   ├── runbooks/
│   │   ├── restore.md
│   │   └── firewall-recovery.md      # NEW — recovering a locked-out host
├── frontend/                         # React 19 + MUI 7 (fork from LPM)
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── eslint.config.js
│   └── src/
│       ├── main.tsx                  # reuse
│       ├── App.tsx                    # reuse
│       ├── components/AppLayout.tsx   # reuse + rebrand "🛡 Firewall Manager"
│       ├── store/authStore.ts         # reuse
│       ├── api/client.ts              # reuse + extend with firewall API objects
│       ├── hooks/useJobWebSocket.ts   # reuse
│       ├── theme/theme.ts             # reuse
│       └── pages/
│           ├── LoginPage.tsx          # reuse
│           ├── SsoCallbackPage.tsx     # reuse
│           ├── MfaSetupPage.tsx        # reuse
│           ├── ProfilePage.tsx         # reuse
│           ├── GroupsPage.tsx          # reuse
│           ├── UsersPage.tsx          # reuse
│           ├── CertificatesPage.tsx    # reuse
│           ├── SettingsPage.tsx        # reuse
│           ├── RepoManagementPage.tsx  # reuse
│           ├── DashboardPage.tsx       # rewrite (firewall metrics)
│           ├── HostsPage.tsx           # rewrite (backend, status, policy set)
│           ├── HostDetailPage.tsx      # rewrite (rules, drift, policy, jobs)
│           ├── RulesPage.tsx           # NEW — rule catalog/editor
│           ├── PolicySetsPage.tsx      # NEW — named rule bundles
│           ├── DeploymentPage.tsx      # NEW — deploy policy sets to hosts
│           ├── JobsPage.tsx            # rewrite (real-time WS)
│           ├── MaintenanceWindowsPage.tsx # reuse
│           └── ReportsPage.tsx         # rewrite (compliance %)
└── scripts/
    └── build-package.sh              # fork from LPM, rename

## Architecture

### Process model

Manager (one host):
- fw-web (Axum) — port 443 HTTPS API + SPA host + internal CA + GPG-signed apt repo on port 80
- fw-worker (background) — polling, jobs, drift detection, audit anchoring, WS relay
- PostgreSQL 16 — single source of truth + IPC (LISTEN/NOTIFY, FOR UPDATE SKIP LOCKED)

Per-host agent:
- fw-agent — Rust daemon, port 12443 mTLS, TLS 1.3
- Detects UFW/firewalld/nftables/iptables (v0.1: UFW + firewalld only)
- Compiles typed rules → backend commands
- Reports drift, health, CRL/GPG status, binary hash, version, container runtime

### Data flow

1. Admin defines Rules (typed rows), groups into PolicySets, assigns to Hosts/Groups.
2. Admin clicks Deploy → manager creates FirewallJob → NOTIFY job_enqueued.
3. fw-worker acquires per-host lock (FOR UPDATE SKIP LOCKED on host_apply_locks), calls fw-agent-client::deploy_rules.
4. fw-agent validates rules against protected CIDRs, compiles to backend commands, applies atomically, captures snapshot, returns result + hash.
5. fw-worker records result + snapshot, releases lock, NOTIFY job_update.
6. fw-web PgListener → browser WS → Jobs page real-time progress.
7. drift_poller (15-min) fetches /rules/snapshot, hashes, compares to drift_snapshots, emits drift_detected on mismatch.
8. Agent self-updates via GPG-signed apt repo on port 80, 300s delayed restart.

## Firewall rule model

### Schema (006 + 008 + 009)

firewall_rules: id, name (unique), description, action (allow/deny/reject/limit/masquerade), direction (in/out/forward), protocol (any/tcp/udp/icmp/icmpv6/gre/esp/ah/sctp), src_cidr (INET), src_port_start/end (1-65535), dst_cidr, dst_port_start/end, interface_in, interface_out, comment, log (bool), priority (int), created_by, created_at, updated_at. CHECK constraints on port ranges.

firewall_policy_sets: id, name (unique), description, created_by, created_at, updated_at.
firewall_policy_set_rules: policy_set_id, rule_id, rule_order (override priority within set).

host_policy_assignments: host_id, policy_set_id, assigned_by, assigned_at (replaces /etc/fw/role.env).

drift_snapshots: host_id, snapshot_hash (SHA256 of normalized rules), rule_count, captured_at, source (job_result|drift_poll).

### Why structured rules

- No shell execution of operator content — eliminates the entire attack class the old validator fought.
- Backend-agnostic — same rule compiles to ufw/firewalld/nftables/iptables commands.
- Auditable — every rule change is a DB row; every deploy is a FirewallJob.
- UI-friendly — dropdowns for action/protocol/direction, CIDR input with validation, port-range picker.
- Versioned & reversible — revert = redeploy prior PolicySet snapshot.

## Security architecture (reused + hardened from LPM)

| Control | Source | Reuse strategy |
|---|---|---|
| JWT Ed25519, 15-min TTL | pm-auth/jwt.rs | Fork to fw-auth, reuse + add jti revocation (SEC-011) |
| Argon2id m=64MiB t=3 p=1 | pm-auth/password.rs | Reuse verbatim |
| TOTP MFA, AES-GCM encrypted at rest | pm-auth/session.rs + pm-core/crypto.rs | Reuse verbatim |
| Account lockout (5/30min) | pm-auth/session.rs | Reuse verbatim |
| RBAC Admin/Operator/Reporter | pm-auth/rbac.rs | Reuse + add Operator host-group scoping + break-glass (SEC-012) |
| IP allowlist + trusted-proxy XFF | pm-auth/rbac.rs | Reuse verbatim (20 spoofing tests) |
| Internal CA (offline root + online intermediate) | pm-ca/ca.rs (NEW design) | Fork + add two-tier CA (SEC-001) |
| mTLS agent client (TLS 1.3, pinned CA) | pm-agent-client/client.rs | Reuse verbatim, swap endpoint types |
| Hash-chained audit log + external anchor | pm-core/audit.rs | Reuse + add external anchoring (SEC-004) |
| AES-256-GCM secrets at rest (2 keys, separated) | pm-core/crypto.rs | Reuse + specify key locations (SEC-010) |
| Rate limiting (3 governor layers) | pm-web/build_router | Reuse verbatim |
| WS ticket flow + Origin allowlist | pm-web/routes/ws.rs | Reuse verbatim |
| Self-enrollment 3-phase + token + CSR | pm-web/routes/enrollment.rs | Reuse + add token + CSR (SEC-002) |
| GPG-signed apt repo on port 80 | pm-web/build_repo_router + pm-core/gpg.rs | Reuse verbatim |
| Per-host API authorization (mTLS cert = principal) | NEW (SEC-008) | New middleware: extract host from cert, refuse body host_id mismatch |
| Rule policy engine | NEW (SEC-003) | New crate: reject broad allows, require 2nd admin approval, enforce protected CIDRs |
| Agent binary integrity | NEW (SEC-007) | Sign agent binary, self-verify at startup, manager tracks hash + min version |
| Container runtime detection | NEW (SEC-005) | Agent detects Docker/Podman/K8s, refuses UFW if present unless Admin override |
| Per-host push serialization | NEW (SEC-013) | FOR UPDATE SKIP LOCKED on host_apply_locks |

## CA architecture (SEC-001)

Air-gapped signing host or KMS/HSM:
  Root CA key (never on manager, never on network)
  └─ Signs intermediate CA cert (1-yr lifetime)

Manager (online):
  Intermediate CA key (encrypted at rest, AES-256-GCM, key from KMS)
  Intermediate CA cert (signed by root)
  Issues per-host agent certs (mTLS, 1-yr lifetime)

Agent package (.deb):
  Root CA cert (pinned by fingerprint at install time, NOT fetched over network)
  Trusts intermediate via chain

CA compromise response (SEC-009 runbook):
  1. Revoke intermediate CA (mark in certificates, generate CRL)
  2. Issue new intermediate signed by root (on air-gapped host)
  3. Ship new intermediate to agents via GPG-signed agent package update
  4. Forced re-enrollment of all agents
  5. Audit all certs issued by compromised intermediate
  6. Document kill switch for root compromise (out-of-scope v0.1, document as limitation)

## Enrollment flow (SEC-002)

1. Admin generates enrollment token in UI: POST /api/v1/admin/enrollment-tokens {fqdn, ip?, ttl_hours} → 64-char token (shown once, SHA-256 stored)
2. Admin delivers token to operator out-of-band (chat, ticket)
3. Operator runs: fw-agent enroll --manager-url https://fwm.internal --token <token>
4. Agent generates keypair locally, builds CSR, submits POST /api/v1/enroll {token, csr, fqdn, ip, os_details}
5. Manager validates token (exists, not expired, not used, FQDN matches), records used_at, validates CSR, intermediate CA signs it, returns PkiBundle {ca_chain, server_cert, crl_pem, repo_config}
6. Agent writes certs to /etc/firewall-agent/certs/, begins normal operation
7. Manager inserts hosts row, logs host_enrolled audit event

Token: single-use, 24h TTL, rate-limited (5/min/IP), every attempt logged.

## Agent (fw-agent) — the new component

Crate: crates/fw-agent/
- main.rs: CLI (--help, enroll, run, status, apply --dry-run, drift-check, --version)
- config.rs: /etc/firewall-agent/config.toml loader
- server.rs: Axum HTTPS server (port 12443, mTLS)
- routes/: health.rs, system_info.rs, rules.rs (snapshot/apply/reset), jobs.rs, pki.rs
- backend/: mod.rs (FirewallBackend trait), ufw.rs, firewalld.rs, nftables.rs (v0.2), iptables.rs (v0.2)
- compiler.rs: typed Rule → backend command vector
- drift.rs: snapshot normalization + hash
- enrollment.rs: 3-phase enrollment client (CSR + token)
- mtls.rs: load certs from /etc/firewall-agent/certs/
- audit.rs: local audit log (/var/log/firewall-agent.log)
- self_update.rs: apt/dnf update path
- container_detect.rs: Docker/Podman/K8s probe (SEC-005)
- protected_cidrs.rs: enforce mgmt-lockout protection (SEC-006)
- safe_mode.rs: revert to last-known-good if manager unreachable (opt-in, SEC-006)
- binary_verify.rs: self-verify GPG signature at startup (SEC-007)

FirewallBackend trait:
  fn name() -> &'static str
  fn detect() -> Option<Self>
  async fn compile(rules: &[FirewallRule]) -> Result<CompiledRules>
  async fn apply(compiled) -> Result<ApplyResult>   // atomic (iptables-restore for UFW, --permanent+--reload for firewalld)
  async fn snapshot() -> Result<NormalizedSnapshot>
  async fn reset() -> Result<()>
  async fn status() -> Result<BackendStatus>

Backend priority: distro native wrapper first (ufw on Ubuntu, firewalld on RHEL) → nftables → iptables.

Agent CLI:
  fw-agent --help
  fw-agent enroll --manager-url https://fwm.internal --token <token>
  fw-agent run                          # daemon mode (systemd)
  fw-agent status                       # one-shot: enrollment, backend, last sync
  fw-agent apply --dry-run               # preview compiled commands
  fw-agent drift-check                  # one-shot: hash rules, compare to snapshot
  fw-agent --version

Agent systemd unit:
  AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
  CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
  # All other LPM hardening (ProtectSystem=strict, ProtectHome, PrivateTmp, etc.)

## Web UI (frontend fork from LPM)

Reused verbatim: React 19 + MUI 7 + Emotion + Zustand persist + axios (with 401-refresh interceptor + failedQueue) + react-router 7 + Vite 6. main.tsx, App.tsx, AppLayout.tsx, authStore.ts, api/client.ts, useJobWebSocket.ts, theme/theme.ts (dark mode, primary #42A5F5, secondary #26C6DA).

New/rewritten pages:
- DashboardPage: fleet-wide # hosts, # in drift, # pending jobs, compliance %, backend distribution
- HostsPage: filterable list with backend, status, last-seen, assigned policy set, container warning
- HostDetailPage: system info, current rules (live snapshot), drift status, policy assignments, jobs, cert
- RulesPage: rule catalog, typed editor form (dropdowns, CIDR input, port-range picker, priority slider)
- PolicySetsPage: drag-reorder, add/remove rules, "preview as backend commands" button
- DeploymentPage: select policy set → select hosts/groups → Preview (dry-run) → Deploy (FirewallJob, WS progress)
- JobsPage: real-time WS, per-host status, retry/rollback
- ReportsPage: compliance %, drift history, deploy history (CSV + PDF via fw-reports)

New UI flows (security review):
- Rule approval workflow: high-risk rules flagged for 2nd Admin approval (SEC-003)
- Break-glass operator flow: audit alert + post-hoc justification within 24h (SEC-012)
- Step-up MFA: re-enter TOTP for high-risk ops (SEC-011)
- Container warning banner: "Docker detected; UFW backend may be bypassed" (SEC-005)
- Protected CIDR config per host (SEC-006)

## Implementation phases

Phase 0 — Scaffolding + design docs (2 days, cumulative 2):
1. Create workspace skeleton: Cargo.toml (8 members), frontend/, migrations/, debian/, systemd/, scripts/, docs/, config/, CI workflows, AGENTS.md, ARCHITECTURE.md, SECURITY.md
2. CA design doc (offline root + online intermediate, key locations, rotation procedure)
3. Key management design doc (AES key separation, KMS/HSM integration points)
4. Fork pm-auth/pm-ca/pm-core/pm-agent-client/pm-reports as fw-* with renames; cargo build --workspace passes
5. Fork LPM frontend shell; rebrand; npm run build passes
6. Fork build/packaging/systemd/Dockerfile/docker-compose with renames
7. Stand up CI; fmt/clippy/test/audit/gitleaks/frontend-lint pass on greenfield

Phase 1 — Domain models + migrations (4 days, cumulative 6):
1. Write firewall migrations (006-010, 033): rules, zones, policy_sets, assignments, drift_snapshots, backend_mappings
2. Write security migrations (011-020): protected_cidrs, policy_decisions, enrollment_tokens, jti_sessions, operator_host_groups, audit_anchor, ca_tier, agent_binary_tracking, container_runtime, per_host_lock
3. Fork LPM migrations 001-005, 021-035 (renaming patch_* → firewall_*, adjusting job_kind enum)
4. Write fw-core/models.rs firewall types: FirewallRule, FirewallPolicySet, HostPolicyAssignment, DriftSnapshot, FirewallJob, FirewallJobHost, ProtectedCidr, RulePolicyDecision, EnrollmentToken, AuditAnchor
5. Extend AuditAction enum: rule_created/updated/deleted, policy_set_created/changed, policy_assigned/unassigned, rule_deployed/rollback, drift_detected, backend_changed, break_glass_used, enrollment_token_issued/used/revoked, ca_intermediate_issued/revoked, audit_anchor_mismatch

Phase 2 — Manager web + worker (5 days, cumulative 11):
1. Fork pm-web → fw-web: rename routes, keep auth/enrollment/settings/ca/pki/ws/reports handlers verbatim, rewrite hosts/groups/jobs/maintenance_windows handlers for firewall domain. Add routes/rules.rs, routes/policy_sets.rs, routes/deployment.rs, routes/preview.rs (compile endpoint)
2. Fork pm-worker → fw-worker: keep health_poller, refresh_listener, maintenance_scheduler, audit_verifier, ws_relay, enrollment_cleanup. Rewrite job_executor to call fw-agent-client::deploy_rules. Add drift_poller (15-min). Add audit_anchor task (daily export + hourly verify). Add per-host serialization (FOR UPDATE SKIP LOCKED on host_apply_locks).
3. Fork pm-agent-client → fw-agent-client: keep mTLS setup, envelope parsing, reconnect. New methods: deploy_rules, reset_rules, get_snapshot, get_health, get_system_info, job_status, rollback_job
4. Add rule policy engine (fw-core/policy.rs): reject broad allows, flag high-risk for 2nd admin approval, enforce protected CIDRs, log decisions
5. Add per-host authz extractor (fw-web/middleware/host_authz.rs): extract host from mTLS cert CN/SAN, refuse body host_id mismatch
6. Add JWT jti revocation check (fw-auth/session.rs): check refresh_tokens.revoked_at on every protected request; on user disable, invalidate all active jtis
7. Add Operator host-group scoping (fw-auth/rbac.rs): check operator_host_groups for target host; break-glass bypass triggers audit + requires post-hoc justification
8. Add agent version/hash tracking: manager records hosts.agent_binary_hash + agent_version, refuses connections below min_supported_version, alerts on unacknowledged hash change

Phase 3 — Agent (6 days, cumulative 17):
1. Stand up fw-agent crate: config loader, mTLS server (Axum on 12443), enrollment client (CSR + token), self-update via apt/dnf
2. Implement FirewallBackend trait + UfwBackend (iptables-save/restore atomicity) + FirewalldBackend (--permanent + --reload). Stub NftablesBackend + IptablesBackend for v0.2.
3. Implement compiler: FirewallRule → Vec<String> per backend. Golden tests.
4. Implement routes: GET /health, GET /system/info, GET /rules/snapshot, POST /rules/apply, POST /rules/reset, GET /jobs/{id}, WS /ws/jobs
5. Implement drift: normalize rules (sorted by priority, then name), SHA256, compare to last snapshot
6. Implement container_detect: probe for Docker/Podman/K8s; refuse UFW if present unless override
7. Implement protected_cidrs: reject rules blocking protected CIDRs, report failed deploy
8. Implement safe_mode: if manager unreachable for N min (default 30, opt-in), revert to last-known-good + local alert
9. Implement binary_verify: GPG self-verify at startup, refuse to run if invalid
10. Implement per-host mutex: reject concurrent /rules/apply while one in flight
11. Implement replay protection: reject deploys with job_id <= last_applied_job_id
12. CLI: --help, enroll, run, status, apply --dry-run, drift-check, --version
13. Integration tests: containerized Ubuntu (UFW) + Alma (firewalld) — apply, snapshot, drift, reset

Phase 4 — Frontend pages (4 days, cumulative 21):
1. RulesPage with typed editor form + validation
2. PolicySetsPage with drag-reorder + preview-as-commands
3. DeploymentPage with host/group picker + Preview + Deploy + WS progress
4. Rewrite HostsPage/HostDetailPage for firewall domain
5. Rewrite DashboardPage for firewall metrics
6. ReportsPage compliance view
7. Rule approval workflow UI (SEC-003)
8. Break-glass operator flow UI (SEC-012)
9. Step-up MFA flow (SEC-011)
10. Container warning banner (SEC-005)
11. Protected CIDR config UI (SEC-006)
12. Keep LoginPage, SsoCallbackPage, MfaSetupPage, ProfilePage, GroupsPage, UsersPage, MaintenanceWindowsPage, CertificatesPage, SettingsPage, RepoManagementPage from LPM fork

Phase 5 — Packaging + docs (2 days, cumulative 23):
1. scripts/build-package.sh for manager .deb
2. Agent .deb build script
3. debian/, systemd/ for both (agent needs CAP_NET_ADMIN + CAP_NET_RAW)
4. docs/REST_API.md, docs/security-review.md
5. docs/ca-compromise-runbook.md (SEC-009)
6. docs/runbooks/restore.md, docs/runbooks/firewall-recovery.md
7. README.md install/config/start guide (fork from LPM)
8. End-to-end test: enroll a host, create rules, deploy, drift-check, rollback

Phase 6 — Hardening + CI (2 days, cumulative 25):
1. cargo audit, cargo clippy --all-targets --all-features, gitleaks
2. Fuzzing for compiler (rule → commands should never panic on any input)
3. Verify systemd hardening on both manager services + agent
4. Integration test: agent A's cert attempts to fetch host B's rules → 403 (SEC-008)
5. CA compromise drill in staging (SEC-009): revoke intermediate, issue new, ship to agents, forced re-enrollment, cert audit
6. Confirm CI passes on v0.1.0 tag → release .deb + Docker image

Total: ~25 days.

## Risks and open items

1. CAP_NET_ADMIN on agent — necessary for firewall manipulation, more privileged than patch agent. Hardened unit file limits to exactly that capability. Acceptable for use case.
2. CSR-based enrollment adds one bootstrap step (agent generates keypair before enrollment). Approved by user.
3. Backend selection: distro native wrapper first (ufw on Ubuntu, firewalld on RHEL) → nftables → iptables. Approved by user.
4. UFW atomicity via iptables-save/iptables-restore (not ufw --force reset). Approved by user.
5. Greenfield — no migration from old bash system. Approved by user.
6. v0.1 ships UFW + firewalld only; nftables + iptables deferred to v0.2. Approved by user.
7. Root CA compromise kill switch — out-of-scope for v0.1, documented as limitation (requires out-of-band verification mechanism for root rotation).

## Security review findings integrated

All 9 Critical + 4 High findings from security auditor review folded in:
- SEC-001: Offline root CA + online intermediate
- SEC-002: One-time per-host enrollment tokens
- SEC-003: Server-side rule policy engine
- SEC-004: Externally anchored audit chain
- SEC-005: Container-host detection
- SEC-006: Management-lockout protection (protected CIDRs + safe mode)
- SEC-007: Agent binary integrity (signing + self-verify + version tracking)
- SEC-008: Per-host API authorization (mTLS cert = principal)
- SEC-009: CA compromise runbook (v0.1 deliverable)
- SEC-010: AES key separation spec (KMS/HSM integration)
- SEC-011: JWT revocation (jti blacklist + step-up MFA)
- SEC-012: Operator host-group scoping + break-glass role
- SEC-013: Per-host push serialization (FOR UPDATE SKIP LOCKED)

Remaining ~44 Medium/Low/Informational findings deferred to v0.1.1 hardening pass (IPv6 handling, ICMP rules, conntrack limits, default-policy management, interface hotplug, NetworkManager interactions, backup/restore of manager DB, key rotation procedures, monitoring hooks, alerting, multi-tenant).