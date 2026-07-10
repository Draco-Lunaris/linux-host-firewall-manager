# Firewall Recovery Runbook

## Overview

This runbook describes how to recover a host that has been locked out of
management communication due to a firewall rule misconfiguration.

## Scenario: Host unreachable after rule deploy

A policy set was deployed that blocked the manager's IP or the management
interface, making the host unreachable from the manager.

### Symptoms

- Host shows `unreachable` health status in the dashboard
- `fw-agent` on the host cannot reach the manager
- SSH access to the host may also be blocked

### Recovery via out-of-band access

1. **Gain out-of-band access** to the host:
   - Cloud provider serial console (AWS Session Manager, GCP Serial Port, Azure Serial Console)
   - IPMI / iLO / iDRAC / BMC
   - Physical console
   - Hypervisor console (if virtualized)

2. **Stop the firewall agent**:
   ```bash
   sudo systemctl stop firewall-agent
   ```

3. **Reset the firewall to a known-good state**:
   - For UFW:
     ```bash
     sudo ufw --force reset
     sudo ufw --force enable
     sudo ufw allow 22/tcp comment 'SSH emergency access'
     sudo ufw allow 12443/tcp comment 'fw-agent'
     ```
   - For firewalld:
     ```bash
     sudo firewall-cmd --permanent --remove-all
     sudo firewall-cmd --permanent --add-service=ssh
     sudo firewall-cmd --permanent --add-port=12443/tcp
     sudo firewall-cmd --reload
     ```

4. **Verify manager connectivity**:
   ```bash
   curl -k https://<manager-ip>:443/status/health
   ```

5. **Restart the agent**:
   ```bash
   sudo systemctl start firewall-agent
   ```

6. **In the manager UI**, redeploy the correct policy set to the host.

### Prevention

- **Protected CIDRs** (SEC-006): configure the manager's IP as a protected
  CIDR on each host. The agent will reject rules that block it.
- **Safe mode** (SEC-006): enable safe mode on critical hosts. If the agent
  can't reach the manager for N minutes, it reverts to the last-known-good
  ruleset.
- **Dry-run preview**: use the "Preview (Dry Run)" button in the Deployment
  page before deploying to verify the compiled commands.
- **Gradual rollout**: deploy to a test host first, verify connectivity,
  then deploy to the rest of the fleet.

## Scenario: Agent in safe mode

If safe mode is enabled and the agent can't reach the manager, it will
revert to the last-known-good ruleset after the timeout (default 30 min).

### Recovery

1. The agent automatically reverts — no action needed if safe mode is working
2. Fix the manager connectivity issue (network, manager service, etc.)
3. The agent will re-establish contact and resume normal operation
4. Check the agent log: `journalctl -u firewall-agent -f`

## Scenario: Agent binary corrupted

If the agent binary is corrupted or replaced by an attacker:

### Symptoms

- Agent won't start (GPG self-verification fails — SEC-007)
- Manager reports audit event
- Manager refuses connections from the agent (version below minimum)

### Recovery

1. Reinstall the agent package:
   ```bash
   sudo apt-get install --reinstall linux-firewall-agent
   ```
2. If the GPG key is also compromised, follow the CA compromise runbook
3. Verify the agent starts: `sudo systemctl start firewall-agent`
4. Check status: `fw-agent status`