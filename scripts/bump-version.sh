#!/bin/bash
# Bump version for linux-host-firewall-manager.
# Version lives only in Cargo.toml (workspace.package.version) and frontend/package.json
# (debian/control is generated inline at build time; there is no debian/changelog).
# Usage: ./scripts/bump-version.sh <new_version> <old_version>
set -euo pipefail

NEW_VERSION="${1:?Usage: bump-version.sh <new_version> <old_version>}"
OLD_VERSION="${2:?Usage: bump-version.sh <new_version> <old_version>}"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "=== Bumping version from $OLD_VERSION to $NEW_VERSION ==="

# 1. Cargo.toml (PRIMARY - workspace.package.version)
sed -i "s/version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
echo "[1/2] Cargo.toml: $OLD_VERSION -> $NEW_VERSION"

# 2. frontend/package.json
if [ -f frontend/package.json ]; then
    sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" frontend/package.json
    echo "[2/2] frontend/package.json: -> $NEW_VERSION"
else
    echo "[2/2] frontend/package.json: Not found, skipping"
fi

echo ""
echo "=== Version bump complete ==="
echo "  Cargo.toml:            $(grep '^version' Cargo.toml | head -1)"
echo "  frontend/package.json: $(grep '\"version\"' frontend/package.json | head -1)"