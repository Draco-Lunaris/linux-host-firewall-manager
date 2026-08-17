#!/bin/bash
set -euo pipefail

# Build script for the linux-firewall-manager-agent .deb (agent-only).
#
# Packages: fw-agent binary and firewall-agent.service. No Postgres, no
# frontend, no migrations — those all live in the manager package.

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

# Ensure Rust toolchain is in PATH
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

# Read version from Cargo.toml workspace section (shared with manager package)
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*=.*"\(.*\)"/\1/')
RELEASE="1"
PACKAGE_NAME="linux-firewall-manager-agent"
DEB_FILE="${PACKAGE_NAME}_${VERSION}-${RELEASE}_amd64.deb"
BUILD_DIR="${PROJECT_ROOT}/package-build-agent"

echo "=== Building ${PACKAGE_NAME} v${VERSION}-${RELEASE} ==="

# Step 1: Build fw-agent (selective — only this crate's binary)
echo "--- Building fw-agent ---"
cargo build --release -p fw-agent
strip target/release/fw-agent

# Step 2: Assemble package
echo "--- Assembling package ---"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/local/bin"
mkdir -p "${BUILD_DIR}/lib/systemd/system"

# Agent binary
cp target/release/fw-agent "${BUILD_DIR}/usr/local/bin/"

# Agent systemd unit
cp systemd/firewall-agent.service "${BUILD_DIR}/lib/systemd/system/"

# DEBIAN/control
cat > "${BUILD_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}-${RELEASE}
Architecture: amd64
Maintainer: Echo <echo@moon-dragon.us>
Depends: openssl, libssl3, libc6 (>= 2.39)
Recommends: gnupg
Section: admin
Priority: optional
Description: Linux Host Firewall Manager — per-host agent
 The agent (fw-agent) is installed on each host you want to centrally
 manage. It pulls its assigned policy from the manager on a configurable
 interval (default ~15 min) over mTLS, applies it locally (UFW or firewalld),
 and reports back. The agent never initiates contact with the manager —
 it pulls, not pushes.
 .
 This package contains fw-agent and firewall-agent.service. The manager
 (fw-web, fw-worker, web UI, SQL migrations) ships in linux-firewall-manager
 and is installed separately on the manager host.
EOF

# DEBIAN/postinst (creates /etc/firewall-agent, /var/log/firewall-agent)
cp debian/agent-postinst "${BUILD_DIR}/DEBIAN/postinst"
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

# DEBIAN/prerm
cp debian/agent-prerm "${BUILD_DIR}/DEBIAN/prerm"
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

# DEBIAN/postrm
cp debian/agent-postrm "${BUILD_DIR}/DEBIAN/postrm"
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

# Step 3: Build .deb
echo "--- Building .deb ---"
# --root-owner-group makes the archive use root:root regardless of the build
# user's uid/gid (avoids dpkg-deb warnings about unusual owner/group).
dpkg-deb --root-owner-group --build "${BUILD_DIR}" "${DEB_FILE}"

# Step 4: Verify
echo "--- Verifying ---"
dpkg-deb --info "${DEB_FILE}"
dpkg-deb --contents "${DEB_FILE}"

echo ""
echo "=== Build complete: ${DEB_FILE} ==="
ls -lh "${DEB_FILE}"
