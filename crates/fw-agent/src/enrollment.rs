//! CSR-based enrollment client (SEC-002).
//!
//! Flow:
//! 1. Agent generates Ed25519 keypair locally
//! 2. Agent builds a CSR with its FQDN
//! 3. Agent submits CSR + one-time token to manager POST /api/v1/enroll
//! 4. Manager validates token, signs CSR with intermediate CA
//! 5. Agent polls GET /api/v1/enroll/status/{polling_token}
//! 6. On approval, agent receives PkiBundle (ca_chain, server_cert, crl_pem, repo_config)
//! 7. Agent writes certs to /etc/firewall-agent/certs/ and saves config

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::{Deserialize, Serialize};

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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
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
                            save_config(manager_url, fqdn)?;
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

fn save_config(manager_url: &str, fqdn: &str) -> Result<()> {
    let config = crate::config::AgentConfig {
        manager_url: manager_url.to_string(),
        fqdn: fqdn.to_string(),
        ..Default::default()
    };
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
}

#[derive(Debug, Deserialize)]
struct PkiBundle {
    ca_chain: Vec<String>,
    server_cert: String,
    crl_pem: Option<String>,
}
