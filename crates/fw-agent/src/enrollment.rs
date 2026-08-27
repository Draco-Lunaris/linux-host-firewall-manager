//! CSR-based enrollment client (SEC-002).
//!
//! Flow:
//! 1. Agent generates Ed25519 keypair locally
//! 2. Agent builds a CSR with its FQDN
//! 3. Agent submits CSR + one-time token to manager POST /api/v1/enroll
//! 4. Manager validates token, signs CSR with intermediate CA
//! 5. Agent polls GET /api/v1/enroll/status/{polling_token}
//! 6. On approval, agent receives PkiBundle (ca_chain, server_cert, crl_pem, pull_config)
//! 7. Agent writes certs to /etc/firewall-agent/certs/ and saves config

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::Deserialize;

const CERT_NAMES: &[(&str, &str)] = &[
    ("ca.pem", "CA certificate (root + intermediate chain)"),
    (
        "server.pem",
        "Agent server certificate (signed by intermediate CA)",
    ),
    (
        "server.key.pem",
        "Agent server private key (Ed25519, PKCS#8)",
    ),
    (
        "crl.pem",
        "Certificate Revocation List (for mTLS peer validation)",
    ),
];

pub async fn enroll(manager_url: &str, token: &str, fqdn: &str) -> Result<()> {
    println!(
        "Starting enrollment for {} with manager {}",
        fqdn, manager_url
    );

    // Step 1: Generate keypair
    let key_pair = KeyPair::generate().context("Failed to generate Ed25519 keypair")?;
    let key_pem = key_pair.serialize_pem();

    // Step 2: Build CSR
    let mut params =
        CertificateParams::new(vec![fqdn.to_string()]).context("Failed to create CSR params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, fqdn);
    dn.push(DnType::OrganizationName, "Firewall Manager");
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key_pair)
        .context("Failed to generate CSR")?;
    let csr_pem = csr.pem().context("Failed to serialize CSR to PEM")?;

    println!("Generated CSR for {}", fqdn);

    // Step 3: Submit enrollment
    // Disable keep-alive pooling so each poll uses a fresh connection — a pooled
    // connection left idle for the 60s poll interval can go stale (server closes
    // it), and reusing it hangs the request until the timeout.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(0)
        .build()?;

    let submit_body = serde_json::json!({
        "token": token,
        "csr": csr_pem,
        "fqdn": fqdn,
        "ip_address": detect_local_ip(),
        "hostname": hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_default(),
        "os_details": detect_os_details(),
    });

    let resp = client
        .post(format!("{}/api/v1/enroll", manager_url))
        .json(&submit_body)
        .send()
        .await
        .context("Failed to submit enrollment request")?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Enrollment submission failed: {}", body);
    }

    let submit_resp: SubmitResponse = resp
        .json()
        .await
        .context("Failed to parse enrollment response")?;
    let polling_token = submit_resp.polling_token;

    println!(
        "Enrollment submitted. Polling for approval (token: {}...)",
        &polling_token[..8.min(polling_token.len())]
    );

    // Step 4: Poll for approval
    let poll_url = format!("{}/api/v1/enroll/status/{}", manager_url, polling_token);
    let max_attempts = 1440; // 24 hours at 60s intervals
    for attempt in 1..=max_attempts {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let resp = client.get(&poll_url).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                if status.as_u16() == 202 {
                    if attempt % 10 == 0 {
                        println!("Still pending (attempt {}/{})", attempt, max_attempts);
                    }
                    continue;
                }
                if status.as_u16() == 403 {
                    anyhow::bail!("Enrollment denied by administrator");
                }
                if status.as_u16() == 404 {
                    anyhow::bail!("Enrollment expired or not found");
                }
                if status.is_success() {
                    let status_resp: EnrollmentStatusResponse = r
                        .json()
                        .await
                        .context("Failed to parse approval response")?;
                    if status_resp.status == "approved" {
                        if let Some(bundle) = status_resp.pki_bundle {
                            println!("Enrollment approved! Writing certificates...");
                            write_pki_bundle(&bundle, &key_pem)?;
                            save_config(
                                manager_url,
                                fqdn,
                                bundle.pull_config.as_ref(),
                                status_resp.host_id.as_deref(),
                            )?;
                            println!("Enrollment complete. Agent ready to run.");
                            return Ok(());
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Poll error (attempt {}): {}", attempt, e);
            }
        }
    }

    anyhow::bail!("Enrollment timed out after 24 hours")
}

fn detect_local_ip() -> String {
    // Try to find the primary non-loopback IPv4 address
    if let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "scope", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                if let Some(addr) = trimmed.strip_prefix("inet ") {
                    if let Some(ip) = addr.split('/').next() {
                        return ip.to_string();
                    }
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

fn detect_os_details() -> serde_json::Value {
    let mut details = serde_json::json!({});
    if let Ok(output) = std::process::Command::new("cat")
        .arg("/etc/os-release")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut os_name = String::new();
        let mut os_version = String::new();
        let mut os_id = String::new();
        for line in stdout.lines() {
            if let Some(val) = line.strip_prefix("NAME=") {
                os_name = val.trim_matches('"').to_string();
            }
            if let Some(val) = line.strip_prefix("VERSION=") {
                os_version = val.trim_matches('"').to_string();
            }
            if let Some(val) = line.strip_prefix("ID=") {
                os_id = val.trim_matches('"').to_string();
            }
        }
        details["os_name"] = serde_json::json!(os_name);
        details["os_version"] = serde_json::json!(os_version);
        details["os_id"] = serde_json::json!(os_id);
    }
    if let Ok(output) = std::process::Command::new("uname").arg("-m").output() {
        let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        details["arch"] = serde_json::json!(arch);
    }
    if let Ok(output) = std::process::Command::new("uname").arg("-r").output() {
        let kernel = String::from_utf8_lossy(&output.stdout).trim().to_string();
        details["kernel"] = serde_json::json!(kernel);
    }
    details
}

fn write_pki_bundle(bundle: &PkiBundle, server_key_pem: &str) -> Result<()> {
    let cert_dir = "/etc/firewall-agent/certs";
    std::fs::create_dir_all(cert_dir).context("Failed to create cert directory")?;

    // Write CA chain
    let ca_pem = bundle.ca_chain.join("\n");
    std::fs::write(format!("{}/ca.pem", cert_dir), ca_pem).context("Failed to write ca.pem")?;

    // Write server cert
    std::fs::write(format!("{}/server.pem", cert_dir), &bundle.server_cert)
        .context("Failed to write server.pem")?;

    // Write server key (the one we generated locally — NOT from the manager)
    std::fs::write(format!("{}/server.key.pem", cert_dir), server_key_pem)
        .context("Failed to write server.key.pem")?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        format!("{}/server.key.pem", cert_dir),
        std::fs::Permissions::from_mode(0o600),
    )?;

    // Write CRL if present
    if let Some(crl) = &bundle.crl_pem {
        std::fs::write(format!("{}/crl.pem", cert_dir), crl).context("Failed to write crl.pem")?;
    }

    println!("Certificates written to {}:", cert_dir);
    for (name, desc) in CERT_NAMES {
        let path = format!("{}/{}", cert_dir, name);
        let exists = std::path::Path::new(&path).exists();
        println!(
            "  {} — {} ({})",
            name,
            desc,
            if exists { "OK" } else { "missing" }
        );
    }

    Ok(())
}

fn save_config(
    manager_url: &str,
    fqdn: &str,
    pull: Option<&BundlePullConfig>,
    host_id: Option<&str>,
) -> Result<()> {
    // Seed the manager's IP as a protected CIDR so the agent never accepts a
    // rule that would block or expose the management interface (SEC-006).
    let protected_cidrs = crate::protected_cidrs::auto_detect_manager_cidr(manager_url)
        .map(|ip| vec![format!("{}/32", ip)])
        .unwrap_or_default();

    let mut config = crate::config::AgentConfig {
        manager_url: manager_url.to_string(),
        fqdn: fqdn.to_string(),
        protected_cidrs,
        ..Default::default()
    };
    // Persist the manager-provided pull config (check-in URL + interval +
    // config version). Without this the check-in loop runs against an empty
    // URL and a zero config version, so the agent can never poll the manager
    // after enrollment.
    if let Some(p) = pull {
        config.pull.check_in_interval_secs = p.check_in_interval_secs;
        // Normalize the manager URL to an IP so the agent has no runtime DNS
        // dependency (required under a default-deny-outgoing policy set). Refuse
        // to save an unresolvable or unspecified manager address rather than
        // enroll a host that could later lock itself out.
        config.pull.manager_agent_url = crate::protected_cidrs::normalize_manager_url_to_ip(
            &p.manager_agent_url,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "manager handed an unusable agent URL ({}): {e}",
                p.manager_agent_url
            )
        })?;
        config.pull.config_version = p.config_version;
    }
    // Persist the manager-assigned host_id. `run_daemon` refuses to start
    // without it (it needs the identity for check-in), so omitting it here
    // would leave the agent enrolled but unable to run.
    if let Some(id) = host_id {
        config.host_id = Some(id.to_string());
    }
    config.save().context("Failed to save agent config")?;
    println!(
        "Config saved to {}",
        crate::config::AgentConfig::config_path()
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    polling_token: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentStatusResponse {
    status: String,
    pki_bundle: Option<PkiBundle>,
    /// Manager-assigned host_id (present on approval). Persisted into config
    /// so the pull loop knows its own identity for check-in.
    host_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PkiBundle {
    ca_chain: Vec<String>,
    server_cert: String,
    crl_pem: Option<String>,
    /// Pull-model config the manager hands the agent on approval. Persisted
    /// into config.toml so the check-in loop knows where to poll and at what
    /// interval. Older managers that omit this field still enroll (serde
    /// defaults the whole `pull_config` to `None`).
    pull_config: Option<BundlePullConfig>,
}

#[derive(Debug, Deserialize)]
struct BundlePullConfig {
    check_in_interval_secs: u32,
    #[serde(default)]
    #[allow(dead_code)]
    push_enabled: bool,
    config_version: i32,
    #[serde(default)]
    manager_agent_url: String,
}
