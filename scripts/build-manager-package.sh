#!/bin/bash
set -euo pipefail

# Build script for the linux-firewall-manager .deb (manager-only).
#
# Packages: fw-web (HTTP/mTLS API + UI), fw-worker (audit anchoring, drift),
#           migrate-secrets (manager one-shot CLI), the React/MUI frontend,
#           SQL migrations, config.example.toml, and the three manager systemd
#           units (firewall-manager-web, firewall-manager-worker,
#           firewall-manager.target).
#
# Does NOT include fw-agent — that ships in linux-firewall-manager-agent.

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

# Ensure Rust toolchain is in PATH
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

# Read version from Cargo.toml workspace section
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*=.*"\(.*\)"/\1/')
RELEASE="1"
PACKAGE_NAME="linux-firewall-manager"
DEB_FILE="${PACKAGE_NAME}_${VERSION}-${RELEASE}_amd64.deb"
BUILD_DIR="${PROJECT_ROOT}/package-build-manager"

echo "=== Building ${PACKAGE_NAME} v${VERSION}-${RELEASE} ==="

# Step 1: Build Rust workspace (we only copy the manager binaries out)
echo "--- Building Rust workspace ---"
cargo build --release
strip target/release/fw-web
strip target/release/fw-worker
strip target/release/migrate-secrets

# Step 2: Build frontend
echo "--- Building frontend ---"
cd frontend
npm ci
npm run build
cd ..

# Step 3: Assemble package
echo "--- Assembling package ---"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/local/bin"
mkdir -p "${BUILD_DIR}/usr/share/firewall-manager/frontend"
mkdir -p "${BUILD_DIR}/usr/share/firewall-manager/migrations"
mkdir -p "${BUILD_DIR}/lib/systemd/system"

# Manager binaries only
cp target/release/fw-web "${BUILD_DIR}/usr/local/bin/"
cp target/release/fw-worker "${BUILD_DIR}/usr/local/bin/"
cp target/release/migrate-secrets "${BUILD_DIR}/usr/local/bin/"

# Frontend
cp -r frontend/dist/* "${BUILD_DIR}/usr/share/firewall-manager/frontend/"

# Migrations
cp migrations/*.sql "${BUILD_DIR}/usr/share/firewall-manager/migrations/"

# Config example (postinst copies it to /etc on first install)
mkdir -p "${BUILD_DIR}/usr/share/firewall-manager"
cp config/config.example.toml "${BUILD_DIR}/usr/share/firewall-manager/config.example.toml"

# Manager systemd units (no agent unit here)
cp systemd/firewall-manager-web.service "${BUILD_DIR}/lib/systemd/system/"
cp systemd/firewall-manager-worker.service "${BUILD_DIR}/lib/systemd/system/"
cp systemd/firewall-manager.target "${BUILD_DIR}/lib/systemd/system/"

# DEBIAN/control
cat > "${BUILD_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}-${RELEASE}
Architecture: amd64
Maintainer: Echo <echo@moon-dragon.us>
Depends: postgresql-16, openssl, curl, libssl3, libc6 (>= 2.39), libfontconfig1, gnupg
Recommends: postgresql-client-16, fonts-dejavu-core
Section: admin
Priority: optional
Description: Enterprise-class centralized host firewall management (manager)
 Linux Host Firewall Manager provides a web-based management plane for
 controlling firewall rules across a fleet of Linux servers and workstations.
 It communicates with managed hosts through a Rust agent over mTLS-secured
 REST endpoints, with support for UFW (Debian/Ubuntu) and firewalld
 (RHEL/Fedora/Alma) backends.
 .
 This package contains the manager (fw-web, fw-worker, migrate-secrets) and
 the web UI. Install linux-firewall-manager-agent on each host you want to
 manage.
EOF

# DEBIAN/postinst
cp debian/postinst "${BUILD_DIR}/DEBIAN/postinst"
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

# DEBIAN/prerm
cp debian/prerm "${BUILD_DIR}/DEBIAN/prerm"
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

# DEBIAN/postrm
cp debian/postrm "${BUILD_DIR}/DEBIAN/postrm"
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

# Step 4: Build .deb
echo "--- Building .deb ---"
# --root-owner-group makes the archive use root:root regardless of the build
# user's uid/gid (avoids dpkg-deb warnings about unusual owner/group).
dpkg-deb --root-owner-group --build "${BUILD_DIR}" "${DEB_FILE}"

# Step 5: Verify
echo "--- Verifying ---"
dpkg-deb --info "${DEB_FILE}"
dpkg-deb --contents "${DEB_FILE}"

echo ""
echo "=== Build complete: ${DEB_FILE} ==="
ls -lh "${DEB_FILE}"
