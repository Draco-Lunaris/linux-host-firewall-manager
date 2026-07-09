# Linux Host Firewall Manager

**Enterprise-class centralized host firewall management for Linux fleets.**

## Overview

Linux Host Firewall Manager provides a web-based management plane for controlling firewall rules across a fleet of Linux servers and workstations. It communicates with managed hosts through a Rust agent over mTLS-secured REST endpoints, with support for UFW (Debian/Ubuntu) and firewalld (RHEL/Fedora/Alma) backends.

## Key Features

- **Centralized Dashboard** — Monitor firewall status, drift, and compliance across all hosts
- **Multi-Backend Support** — UFW and firewalld (nftables + iptables planned for v0.2)
- **Structured Rule Model** — Typed, validated firewall rules (no shell scripts, no injection surface)
- **Policy Sets** — Named bundles of rules assigned to hosts or groups
- **Drift Detection** — Agent reports rule snapshots; manager detects and alerts on drift
- **Secure by Design** — mTLS with internal CA, RS256 (RSA 2048-bit) JWT, Argon2id, TOTP MFA, hash-chained audit log
- **Self-Enrollment** — CSR-based enrollment with one-time tokens and admin approval
- **Agent Self-Update** — GPG-signed apt/dnf repo for agent updates

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
| **Network** | HTTPS (port 443) + HTTP (port 80, GPG repo) |

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

## License

Apache License 2.0

Copyright 2025-2026 Draco Lunaris