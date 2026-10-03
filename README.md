# Linux Host Firewall Manager

Centralized host firewall management for Linux fleets, written in Rust and designed so that the management system does not become the easiest way into the hosts it protects.

Three rules shape the design:

1. **Hosts pull; the manager never pushes.** Each agent checks in and pulls its policy. The manager holds no credentials for any host and never opens a connection to one.
2. **Rules are data, never scripts.** A firewall rule is a typed database row. Nothing an operator enters is ever handed to a shell.
3. **The certificate is the identity.** A host is whoever its mTLS client certificate says it is. A host ID in a request body is never trusted.

## Status

Pre-1.0 and in active development. UFW (Debian/Ubuntu) is the complete backend. The firewalld backend (RHEL/Fedora/Alma) works but is partial; see [Known limitations](#known-limitations). Both are exercised against real firewalls in container integration tests. nftables and iptables backends are planned.

## How it works

```
┌─────────────────────────────┐
│  Firewall Manager (Web UI)   │  ← This project
│   (Management Plane)         │
└──────────┬──────────────────┘
           │  mTLS / REST API
    ┌──────┼──────┐
    ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐
│ Host ││ Host ││ Host │  ← fw-agent (per-host daemon)
│  A   ││  B   ││  C   │
└──────┘└──────┘└──────┘
```

Rules are organized into reusable **rule groups**. Rule groups are assembled, in order, into **policy sets**, and policy sets are assigned to hosts or host groups. A change to a rule group reaches every policy set, and every host, that includes it.

Each agent checks in on a configurable interval (15 minutes by default), pulls its assigned policy, compiles it for the local firewall backend, applies it, and reports the result. An operator can ask for an early check-in; that signal travels over a connection the agent already holds open, so the manager still never dials out.

## Security model

### No inbound path to managed hosts

Push-based configuration management needs standing remote access to every machine it manages, which makes the management server a single point of compromise for the fleet. Here there is no push path, no deploy path, and no manager-to-agent client in the codebase. Compromising the manager does not yield a login on any host.

A compromised manager can still change firewall policy across the fleet, which is serious. It cannot run commands on a host: the actions an agent accepts from the manager are a short fixed list, and anything else is rejected.

### No shell

- A rule is a typed record: action, direction, and protocol are database enums, addresses are stored as `inet`, and ports are integers.
- The agent compiles those records into a `ufw` or `firewall-cmd` command line, splits it into arguments, and executes the tool directly. No shell is invoked anywhere in the codebase, so shell metacharacters in a rule have no effect.
- Operators never supply scripts or command fragments. There is no field for one.

### mTLS and per-host authorization

- Agents connect to a dedicated listener that requires a client certificate signed by the manager's CA. A connection without one fails the TLS handshake and is dropped before any handler runs.
- The manager signs each agent's certificate with the host's ID as its common name. Every agent API call takes its host identity from that certificate, so one host cannot read or report on another. Network tests cover the binding, the rejection of a connection with no client certificate, and the rejection of a revoked one.
- Revoking a certificate regenerates the CRL and swaps the listener's verifier in place, so revocation takes effect without a restart.
- The manager runs its own root CA. An upstream intermediate can be imported as the issuing CA without re-enrolling hosts that are already managed.

### Enrollment

- The agent generates its Ed25519 key pair locally. The private key never leaves the host.
- It submits a certificate signing request with a one-time enrollment token. Tokens are stored only as SHA-256 hashes, expire, and can be used once.
- An administrator approves each host before a certificate is issued.

### Operator access

- Argon2id password hashing, TOTP multi-factor authentication, and optional OIDC single sign-on.
- EdDSA (Ed25519) access tokens with a 15-minute lifetime and per-token revocation.
- Account lockout after repeated failed logins, request rate limiting, and an IP allowlist that handles trusted proxies correctly.
- Four roles: admin, operator, reporter, and break-glass operator. Operators are scoped to the host groups they are assigned.

### Data at rest and audit

- The OIDC client secret, SMTP password, and TOTP secrets are encrypted with AES-256-GCM under a dedicated key file.
- Administrative actions are written to a hash-chained audit log. Each entry's SHA-256 hash covers the previous entry's hash, so an edited or deleted record breaks the chain.
- A worker exports the chain head daily for external anchoring.

### Hardened services

- The manager runs as an unprivileged user whose only capability is binding low ports.
- The agent's capabilities are bounded to `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- Both run under systemd with `NoNewPrivileges`, `ProtectSystem=strict`, a private `/tmp`, protected kernel tunables and modules, and restricted namespaces.

## Guardrails

A firewall manager's most likely failure is locking an operator out of their own hosts. These checks exist to prevent that.

| Guardrail | What it does |
|---|---|
| Protected CIDRs | The agent refuses any deny or reject rule that overlaps a protected network, such as the management subnet. The whole apply is rejected, not just the rule. |
| Manager reachability | On UFW, every apply keeps the agent's path to the manager open, and the agent refuses to apply a policy at all if it can't establish that path first. |
| Broad-allow gate | A rule that allows any source on any port is flagged. Only an admin can assign a policy set that contains one. |
| Drift self-healing | Each cycle the agent hashes the live ruleset. If someone changed it out of band, the agent re-applies the assigned policy. The manager sees the drift either way. |
| Safe mode | Opt-in per host. If the agent can't reach the manager for a configured period (30 minutes by default), it reverts to its last-known-good ruleset. |
| Serialized applies | A per-host lock keeps two applies from racing. |
| Replay protection | A re-delivered action is recognized and not executed twice. |
| Stale agent detection | A host that stops checking in is marked degraded, then unreachable. |
| Container runtime detection | The agent detects Docker, Podman, or Kubernetes and warns that UFW may conflict with container networking. |

## Features

- **Centralized dashboard** for firewall status and drift across all hosts
- **Rule groups and policy sets** for reusable, ordered rules
- **UFW backend**, with a partial firewalld backend
- **Self-enrollment** with one-time tokens and admin approval
- **Turnkey packages**: separate `.deb` packages for the manager and the agent

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Ubuntu 24.04 LTS (Noble) |
| **Database** | PostgreSQL 16 |
| **Memory** | 2 GB RAM minimum, 4 GB recommended |
| **Storage** | 1 GB for application + database |
| **Network** | HTTPS (port 443, web UI/API) + mTLS (port 8443, agent check-in) |

## Building from Source

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Node.js 18+
sudo apt install -y nodejs npm

# Build dependencies
sudo apt install -y pkg-config libssl-dev postgresql-16

# Build
cargo build --release
cd frontend && npm ci && npm run build
```

## Quick Start

```bash
# Install the .deb package (pulls in PostgreSQL 16 automatically)
sudo dpkg -i linux-firewall-manager_*.deb
sudo apt-get install -f  # fix dependencies
```

The first install is turnkey — the package creates the `firewall_manager`
PostgreSQL role and database with a random 25-character password, writes
`/etc/firewall-manager/config.toml` with that password, generates the JWT
keys and a self-signed TLS certificate, and starts the web + worker services.

At the end of the install, the one-time initial admin password is printed:

```
========================================
  INITIAL ADMIN PASSWORD (shown once)
  Username: admin
  Password: <password>
========================================
```

Save it now — it is shown only once. If you missed it:

```bash
sudo journalctl -u firewall-manager-web | grep -A 3 'INITIAL ADMIN PASSWORD'
```

Then open `https://<server-ip>:443`, log in as `admin`, and change the
password immediately after first login.

### Installing the agent on a managed host

The manager and agent ship as **separate `.deb` packages**. Install the
agent on each host you want to centrally manage. During the install you
will be prompted for the manager URL, this host's FQDN, and (optionally) a
one-time enrollment token from the manager web UI (Hosts > Enroll):

```bash
# On each managed host (not the manager host):
sudo dpkg -i linux-firewall-manager-agent_<version>-1_amd64.deb
```

The install is turnkey: the answers are written to
`/etc/firewall-agent/config.toml`, the token (if supplied) is stored
root-only at `/etc/firewall-agent/enroll.token`, and the service starts
and enrolls immediately — you only need to **approve the host** in the
manager web UI (Hosts > Pending).

To pre-answer the prompts non-interactively (e.g. automation):

```bash
echo 'firewall-agent firewall-agent/manager-url string https://fwm.example.com:443' | sudo debconf-set-selections
echo 'firewall-agent firewall-agent/fqdn string host.example.com' | sudo debconf-set-selections
echo 'firewall-agent firewall-agent/enroll-token password <TOKEN>' | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive dpkg -i linux-firewall-manager-agent_<version>-1_amd64.deb
```

If you skipped the token at install time, drop it in place and restart:

```bash
echo '<TOKEN>' | sudo tee /etc/firewall-agent/enroll.token
sudo systemctl restart firewall-agent
```

The agent pulls its assigned policy from the manager over mTLS on a
configurable interval (default ~15 min). The agent always initiates
that contact; the manager never connects to the agent.

## Operations

- [Firewall recovery runbook](docs/runbooks/firewall-recovery.md): a host unreachable after a rule change, an agent in safe mode
- [Restore runbook](docs/runbooks/restore.md)
- [CA compromise runbook](docs/ca-compromise-runbook.md): intermediate key, root key, and manager host compromise

## Development

```bash
just check   # format, clippy, tests, cargo-audit, frontend lint and typecheck
just itest   # UFW and firewalld backends against real firewalls in containers
```

CI runs all of the above plus secret scanning on every change. Packages are built only when every check passes.

## Known limitations

- **UFW applies are not atomic.** The agent runs `ufw reset` and replays the ruleset, which leaves a brief window with rules cleared. An atomic apply is planned.
- **Audit anchors are recorded but not yet verified** against an external store.
- **No agent self-update.** Agents are updated by the operator through the system package manager.
- **The firewalld backend is partial.** It compiles source address, a single destination port, protocol, and action, for IPv4 only. It does not yet honor destination address, port ranges, interfaces, or per-policy defaults.
- **nftables and iptables backends are not implemented yet.**
- **Container hosts get a warning, not a fix.** UFW and container networking can still conflict.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2025-2026 Draco Lunaris
