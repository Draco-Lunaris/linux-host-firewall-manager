# CA Compromise Runbook

## Overview

This runbook describes the procedure for responding to a compromise of the
Firewall Manager's Certificate Authority (CA). The system uses a two-tier
CA model: an offline root CA and an online intermediate CA (SEC-001).

## Threat scenarios

1. **Intermediate CA key compromised** — attacker can mint agent certs
2. **Root CA key compromised** — attacker can mint intermediate CAs (worst case)
3. **Manager host compromised** — both CA keys may be at risk if stored together

## Scenario 1: Intermediate CA key compromised

This is the more likely scenario. The intermediate CA key lives on the
manager host. If the manager is compromised, the attacker can issue certs
for any host.

### Response

1. **Revoke the compromised intermediate CA**
   ```sql
   UPDATE certificates SET status = 'revoked', revoked_at = NOW()
   WHERE ca_tier = 'intermediate' AND status = 'active';
   ```

2. **Generate a new intermediate CA cert** signed by the offline root CA
   - On the air-gapped signing host, load the root CA key
   - Generate a new intermediate CA cert with a new serial number
   - Copy the new intermediate CA cert to the manager

3. **Ship the new intermediate CA cert to all agents**
   - Build a new agent package that includes the new intermediate CA cert
   - Publish via the GPG-signed apt repo (port 80)
   - Agents update via standard package update, then restart

4. **Force re-enrollment of all agents**
   - Revoke all host certs in the `certificates` table
   - Generate new enrollment tokens for each host
   - Operators run `fw-agent enroll` with the new tokens
   - New certs are signed by the new intermediate CA

5. **Audit all certs issued by the compromised intermediate**
   ```sql
   SELECT * FROM certificates
   WHERE ca_tier = 'intermediate'
   AND issued_at >= '<compromise_start_date>'
   AND issued_at <= '<compromise_end_date>'
   ORDER BY issued_at;
   ```

6. **Generate a new CRL** that revokes all certs from the compromised intermediate
   - The manager's `generate_crl` function will include all revoked certs

7. **Document the incident** in the audit log with `ca_intermediate_revoked` action

### Estimated downtime

- 2-4 hours for a small fleet (<50 hosts)
- 4-8 hours for a large fleet (500+ hosts)

## Scenario 2: Root CA key compromised

This is the worst case. The root CA key is stored offline (air-gapped host
or KMS/HSM). If it's compromised, the attacker can create new intermediate
CAs that agents will trust.

### Response

1. **Follow Scenario 1 steps** (revoke intermediate, issue new intermediate)

2. **Additionally: distribute a new root CA cert to all agents**
   - This requires an out-of-band mechanism because the old root CA
     cannot sign the "trust the new root" message (it's compromised)
   - Build a new agent package that includes the new root CA cert,
     pinned by fingerprint
   - The agent package is signed with the GPG key (which is separate
     from the CA key), so agents can verify the package integrity
   - Operators must manually install the new agent package on each host,
     or use the existing GPG-signed apt repo if the GPG key is not compromised

3. **Kill switch**: the new agent package refuses to trust the old root CA
   - The agent's cert store is replaced entirely
   - Old certs signed by the old root/intermediate chain are rejected

4. **Re-enroll all agents** with the new root + intermediate CA

### Estimated downtime

- 4-8 hours for a small fleet
- 1-2 days for a large fleet (requires out-of-band agent package distribution)

## Scenario 3: Manager host compromised

If the manager host itself is compromised, both the intermediate CA key
and the JWT signing key may be at risk. The AES encryption keys for
secrets-at-rest are also on the manager.

### Response

1. **Isolate the manager host** — disconnect from the network

2. **Follow Scenario 1** (revoke intermediate, issue new intermediate)

3. **Rotate the JWT signing key**
   - Generate new Ed25519 keys
   - Replace `/etc/firewall-manager/jwt/signing.pem` and `verify.pem`
   - All active JWTs become invalid; users must re-login

4. **Rotate the AES encryption keys**
   - Generate new keys at `/etc/firewall-manager/keys/`
   - Re-encrypt all secrets (OIDC client_secret, SMTP password, TOTP secrets)
   - Use the `migrate-secrets` binary with the new key

5. **Rebuild the manager host** from a known-good state
   - Reinstall the OS or restore from a known-good backup
   - Reinstall the firewall-manager package
   - Restore the database from a known-good backup (verify audit chain integrity first)

6. **Audit the compromise**
   - Check audit log for unauthorized actions during the compromise window
   - Verify audit chain integrity: `SELECT * FROM verify_integrity();`
   - Check for unauthorized rule deploys, user creations, or config changes

## Prevention

- **Offline root CA**: the root CA key never touches the manager host
- **HSM/KMS for intermediate**: if available, store the intermediate CA key
  in an HSM or KMS rather than on disk
- **Network segmentation**: the manager should be on a restricted network
  with limited access
- **Monitoring**: alert on unexpected cert issuance, CRL generation, or
  CA key access
- **Regular key rotation**: rotate the intermediate CA key annually
- **Audit log anchoring**: the daily external anchor (SEC-004) ensures
  that a compromised manager cannot rewrite audit history undetected