# Linux Host Firewall Manager

**Enterprise-class centralized host firewall management for Linux fleets.**

## Overview

Linux Host Firewall Manager provides a web-based management plane for controlling firewall rules across a fleet of Linux servers and workstations. It communicates with managed hosts through a Rust agent over mTLS-secured REST endpoints, with support for UFW (Debian/Ubuntu) and firewalld (RHEL/Fedora/Alma) backends.

Rules are organized into reusable **rule groups**, which are assembled into **policy sets** that are assigned to hosts — so a change to a rule group propagates to every policy set (and host) that includes it.

## Key Features

- **Centralized Dashboard** — Monitor firewall status and drift across all hosts
- **Rule Groups** — Reusable, ordered bundles of rules; edit a group once and it propagates to every policy set that includes it
- **Policy Sets** — Ordered collections of rule groups, assigned to hosts or groups
- **Multi-Backend Support** — UFW (Debian/Ubuntu) and firewalld (RHEL/Fedora/Alma); nftables + iptables planned
- **Structured Rule Model** — Typed, validated firewall rules (no shell scripts, no injection surface)
- **Drift Detection** — The manager compares the agent's applied-policy hash to the assigned policy; the agent self-heals out-of-band changes
- **Agent Pull Model** — Agents check in on a configurable interval (default 15 min) and pull their assigned policy; the manager never initiates contact (an operator can nudge an early check-in via a long-lived SSE signal)
- **Secure by Design** — mTLS with an internal CA, EdDSA (Ed25519) JWTs, Argon2id passwords, TOTP MFA, hash-chained audit log
- **Self-Enrollment** — CSR-based enrollment with one-time tokens and admin approval

## Architecture

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
agent on each host you want to centrally manage:

```bash
# On each managed host (not the manager host):
sudo dpkg -i linux-firewall-manager-agent_<version>-1_amd64.deb
sudo systemctl enable --now firewall-agent.service
```

The agent pulls its assigned policy from the manager over mTLS on a
configurable interval (default ~15 min). It does **not** initiate contact
with the manager; the manager never connects to the agent.

## License

Apache License 2.0

Copyright 2025-2026 Draco Lunaris