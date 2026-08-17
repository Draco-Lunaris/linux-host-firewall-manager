# Linux-Host-Firewall-Manager task runner — single source of truth for local + CI.
# Local:   just check           (dev loop; warm cache on the dev box)
# Release: just release patch    (bump -> commit -> tag -> push; CI builds official .deb)

default:
    @just --list

# one-time: install the cargo tools the gates need
tools:
    cargo install cargo-audit --locked

# --- quality gates (the dev loop; `just check` runs all) ---
fmt:
    cargo fmt --all -- --check

# NOTE: matches current CI intent but without -D warnings; the tree has ~4 pre-existing
# Clippy gate — warnings are errors. The pre-existing lints (type_complexity,
# unnecessary closure, dead fields, io_other_error, manual_async_fn) were fixed
# and the fw-agent #![allow(dead_code)] attrs dropped, so the tree is clean.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features --lib --bins --tests

audit:
    cargo audit

# --- frontend gates ---
frontend-deps:
    @cd frontend && [ -d node_modules ] || npm ci

frontend-lint: frontend-deps
    cd frontend && npx eslint src/ --ext .ts,.tsx --max-warnings 0

frontend-typecheck: frontend-deps
    cd frontend && npx tsc --noEmit

frontend-build: frontend-deps
    cd frontend && npm run build

check: fmt clippy test audit frontend-lint frontend-typecheck
    @echo "all gates passed"

# --- build / package ---
build:
    cargo build --release

# system deps (lifted from ci.yml; run on the matching distro)
deps-deb:
    sudo apt-get update && sudo apt-get install -y pkg-config libssl-dev libfontconfig1-dev dpkg-dev

# build the manager .deb (fw-web, fw-worker, migrate-secrets, frontend,
# migrations, config example, 3 manager systemd units)
pkg-manager-deb:
    bash scripts/build-manager-package.sh

# build the agent .deb (fw-agent, firewall-agent.service)
pkg-agent-deb:
    bash scripts/build-agent-package.sh

# build both .debs; legacy alias for older dev muscle memory
pkg-deb: pkg-manager-deb pkg-agent-deb

# --- version bump (helper for release) ---
bump-version NEW OLD:
    bash scripts/bump-version.sh "{{NEW}}" "{{OLD}}"

# --- release (CI remains the official builder) ---
release KIND:
    bash scripts/release.sh "{{KIND}}"