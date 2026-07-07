# Disaster Recovery — Manager DB Restore

## Overview

This runbook describes how to restore the Firewall Manager database from
a backup.

## Prerequisites

- A PostgreSQL backup (pg_dump or pg_basebackup)
- The AES encryption keys at `/etc/firewall-manager/keys/` (must be the
  same keys used when the backup was taken — secrets at rest are encrypted
  with these keys)

## Procedure

1. **Stop the manager services**:
   ```bash
   sudo systemctl stop firewall-manager.target
   ```

2. **Drop and recreate the database**:
   ```bash
   sudo -u postgres dropdb firewall_manager
   sudo -u postgres createdb firewall_manager
   sudo -u postgres psql -c "GRANT ALL ON DATABASE firewall_manager TO firewall_manager;"
   ```

3. **Restore from backup**:
   ```bash
   sudo -u postgres psql firewall_manager < /path/to/backup.sql
   ```

4. **Verify audit chain integrity**:
   ```sql
   SELECT * FROM verify_integrity();
   ```
   If the chain is broken, investigate before proceeding — the backup
   may have been tampered with.

5. **Restore the encryption keys** (if the manager host was rebuilt):
   ```bash
   sudo cp /path/to/backup/keys/health-check.key /etc/firewall-manager/keys/
   sudo cp /path/to/backup/keys/secret-encryption.key /etc/firewall-manager/keys/
   sudo chmod 600 /etc/firewall-manager/keys/*
   sudo chown firewall-manager:firewall-manager /etc/firewall-manager/keys/*
   ```

6. **Start the manager services**:
   ```bash
   sudo systemctl start firewall-manager.target
   ```

7. **Verify**:
   - Check `journalctl -u firewall-manager-web -f` for startup errors
   - Access the web UI and verify hosts are visible
   - Run a health check on a few hosts

## Backup strategy

- **Daily pg_dump** with `--format=custom` for fast restore
- **Weekly pg_basebackup** for PITR capability
- **Off-site backup** of the encryption keys (separate from the DB backup)
- **Audit log external anchor** (SEC-004) provides tamper evidence even
  if the DB backup is modified