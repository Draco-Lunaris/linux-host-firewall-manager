//! Ensure the agent mTLS listener serves a CA-signed cert.
//!
//! The agent pull client validates the manager's server cert against the CA
//! cert it pins at enrollment, so the 8443 listener must serve a cert that
//! chains to the manager CA — the self-signed web cert (443) does not, and
//! reusing it makes every check-in fail TLS validation. On startup the manager
//! therefore issues its own listener cert from `fw_ca` if the configured one is
//! missing, unreadable, expiring soon, or its SANs no longer match the config.

use fw_ca::{CertAuthority, ServerCert};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Re-issue an existing cert once it is this close to expiry (the listener
/// keeps serving whatever was loaded at startup, so an expired cert would
/// strand the agents until the next restart).
const REISSUE_MARGIN_DAYS: i64 = 30;

/// Failures while ensuring the agent-listener cert.
#[derive(Debug, thiserror::Error)]
pub enum CertEnsureError {
    #[error("CA server-cert issue failed: {0}")]
    Issue(#[from] fw_ca::CertError),
    #[error("cert file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("cert parse failed: {0}")]
    Parse(String),
}

/// Outcome of an ensure pass, for startup logging.
#[derive(Debug, PartialEq, Eq)]
pub enum CertOutcome {
    /// The existing cert is usable as-is.
    Reused,
    /// A cert was written to disk (fresh or replaced).
    Issued,
}

/// Ensure a CA-signed listener cert exists at `cert_path` / `key_path`.
///
/// Reuses the existing cert when it is readable, valid for longer than the
/// re-issue margin, and carries exactly the configured SANs; otherwise issues a
/// replacement from the manager CA. The key is written with 0600.
pub fn ensure_agent_listener_cert(
    ca: &CertAuthority,
    cert_path: &str,
    key_path: &str,
    sans: &[String],
) -> Result<CertOutcome, CertEnsureError> {
    let reusable = match std::fs::read_to_string(cert_path) {
        Ok(pem) => existing_cert_reusable(&pem, sans),
        Err(_) => None,
    };

    if reusable == Some(true) && std::path::Path::new(key_path).exists() {
        return Ok(CertOutcome::Reused);
    }

    let reason = match reusable {
        Some(true) => "key missing",
        Some(false) => "expiring soon or unreadable",
        None => "missing",
    };
    tracing::info!(cert_path, reason, "issuing CA-signed agent-listener cert");

    let ServerCert { cert_pem, key_pem } = ca.issue_server_cert(sans)?;
    std::fs::write(cert_path, cert_pem)?;
    std::fs::write(key_path, key_pem)?;
    restrict_key_permissions(key_path);

    Ok(CertOutcome::Issued)
}

/// `Some(true)` if the existing cert parses, outlives the re-issue margin, and
/// carries exactly the configured SANs; `Some(false)` if the cert parses but
/// fails those checks; `None` if it is unreadable or unparsable.
fn existing_cert_reusable(cert_pem: &str, sans: &[String]) -> Option<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let cert = pem.parse_x509().ok()?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    let margin = REISSUE_MARGIN_DAYS * 24 * 3600;
    if cert.validity().not_after.timestamp() <= now + margin {
        return Some(false);
    }

    let cert_sans = cert_san_strings(&cert)?;
    Some(cert_sans == canonical_sans(sans))
}

/// The cert's SANs, canonicalized the same way as [`canonical_sans`].
fn cert_san_strings(cert: &X509Certificate<'_>) -> Option<Vec<String>> {
    let san = cert.subject_alternative_name().ok()??;
    let mut out = Vec::new();
    for name in san.value.general_names.iter() {
        match name {
            GeneralName::DNSName(dns) => out.push(dns.to_string()),
            GeneralName::IPAddress(bytes) => {
                let ip = match bytes.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(*bytes).ok()?),
                    16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).ok()?),
                    _ => return None,
                };
                out.push(ip.to_string());
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The configured SANs, with IPs normalized to their canonical string form so
/// they compare equal to the canonical forms a cert carries (e.g. `::0.0.0.1`
/// vs `::1`).
fn canonical_sans(sans: &[String]) -> Vec<String> {
    sans.iter()
        .map(|san| match san.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => san.clone(),
        })
        .collect()
}

fn restrict_key_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Build the agent-listener `ServerConfig`: the CA-signed agent cert, with a
/// freshly generated CRL fed into the client verifier (revoked client certs
/// are rejected at the TLS handshake). Used at startup and again on every
/// revocation, when the rebuilt config is hot-swapped into the listener.
pub async fn build_agent_tls_config(
    ca: &fw_ca::CertAuthority,
    db: &sqlx::PgPool,
    config: &fw_core::config::AppConfig,
) -> Result<std::sync::Arc<rustls::ServerConfig>, anyhow::Error> {
    let crl_pem = ca.generate_crl(db).await?;
    let server_cert_pem = std::fs::read_to_string(&config.security.agent_tls_cert_path)?;
    let server_key_pem = std::fs::read_to_string(&config.security.agent_tls_key_path)?;
    Ok(crate::agent_listener::build_agent_server_config(
        ca.root_cert_pem(),
        &server_cert_pem,
        &server_key_pem,
        std::slice::from_ref(&crl_pem),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA plus its PEM, mirroring what `CertAuthority::init` produces.
    fn test_ca() -> (CertAuthority, String) {
        // CertAuthority needs a Postgres pool for its first-run bookkeeping; the
        // pool row persistence is skipped when the CA files already exist, so
        // seed the files first via rcgen directly.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let cert_pem = params.self_signed(&ca_key).unwrap().pem();

        let dir = std::env::temp_dir().join(format!("agent-cert-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.to_str().unwrap().to_string();
        std::fs::write(format!("{base}/ca.pem"), &cert_pem).unwrap();
        std::fs::write(format!("{base}/ca.key.pem"), ca_key.serialize_pem()).unwrap();

        // init() with existing files takes the load path — no pool touch. The
        // lazy pool still needs a Tokio context at creation, hence block_on.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ca = rt
            .block_on(async {
                let pool = sqlx::postgres::PgPool::connect_lazy(
                    "postgres://unused:unused@localhost/unused",
                )
                .unwrap();
                fw_ca::CertAuthority::init(base.clone(), &pool).await
            })
            .unwrap();
        rt.shutdown_timeout(std::time::Duration::from_millis(100));
        (ca, cert_pem)
    }

    #[test]
    fn issued_cert_chains_to_ca_and_carries_sans() {
        let (ca, ca_pem) = test_ca();
        let sans = vec!["fwm.example.test".to_string(), "10.0.0.5".to_string()];
        let cert = ca.issue_server_cert(&sans).unwrap();

        // Parses and carries the requested SANs (IP vs DNS classified).
        let (_, pem) = parse_x509_pem(cert.cert_pem.as_bytes()).unwrap();
        let parsed = pem.parse_x509().unwrap();
        assert_eq!(
            cert_san_strings(&parsed).unwrap(),
            vec!["fwm.example.test".to_string(), "10.0.0.5".to_string()]
        );
        // ServerAuth EKU present, and the leaf verifies against the CA cert.
        let eku = parsed.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth);
        assert!(!eku.client_auth);
        let (_, ca_pem_parsed) = parse_x509_pem(ca_pem.as_bytes()).unwrap();
        let ca_cert = ca_pem_parsed.parse_x509().unwrap();
        parsed
            .verify_signature(Some(ca_cert.public_key()))
            .expect("leaf must chain to the issuing CA");
    }

    #[test]
    fn ensure_issues_when_missing_and_reuses_after() {
        let (ca, _) = test_ca();
        let dir = std::env::temp_dir().join(format!("agent-cert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = format!("{}/agent-cert.pem", dir.to_str().unwrap());
        let key_path = format!("{}/agent-key.pem", dir.to_str().unwrap());
        let sans = vec!["localhost".to_string()];

        assert_eq!(
            ensure_agent_listener_cert(&ca, &cert_path, &key_path, &sans).unwrap(),
            CertOutcome::Issued
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "issued key must be 0600"
        );
        // Second pass with the same SANs reuses the file untouched.
        let before = std::fs::read_to_string(&cert_path).unwrap();
        assert_eq!(
            ensure_agent_listener_cert(&ca, &cert_path, &key_path, &sans).unwrap(),
            CertOutcome::Reused
        );
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), before);
    }

    #[test]
    fn ensure_reissues_when_sans_change() {
        let (ca, _) = test_ca();
        let dir = std::env::temp_dir().join(format!("agent-cert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = format!("{}/agent-cert.pem", dir.to_str().unwrap());
        let key_path = format!("{}/agent-key.pem", dir.to_str().unwrap());

        ensure_agent_listener_cert(&ca, &cert_path, &key_path, &["localhost".to_string()]).unwrap();
        let before = std::fs::read_to_string(&cert_path).unwrap();
        assert_eq!(
            ensure_agent_listener_cert(&ca, &cert_path, &key_path, &["manager.test".to_string()])
                .unwrap(),
            CertOutcome::Issued,
            "a SAN config change must re-issue the cert"
        );
        let (_, pem) =
            parse_x509_pem(std::fs::read_to_string(&cert_path).unwrap().as_bytes()).unwrap();
        let parsed = pem.parse_x509().unwrap();
        assert_eq!(
            cert_san_strings(&parsed).unwrap(),
            vec!["manager.test".to_string()]
        );
        assert_ne!(std::fs::read_to_string(&cert_path).unwrap(), before);
    }

    #[test]
    fn ensure_reissues_unparsable_cert() {
        let (ca, _) = test_ca();
        let dir = std::env::temp_dir().join(format!("agent-cert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = format!("{}/agent-cert.pem", dir.to_str().unwrap());
        let key_path = format!("{}/agent-key.pem", dir.to_str().unwrap());
        std::fs::write(&cert_path, "not a cert").unwrap();

        assert_eq!(
            ensure_agent_listener_cert(&ca, &cert_path, &key_path, &["localhost".to_string()])
                .unwrap(),
            CertOutcome::Issued,
            "an unreadable existing cert must be replaced"
        );
        parse_x509_pem(std::fs::read_to_string(&cert_path).unwrap().as_bytes())
            .unwrap()
            .1
            .parse_x509()
            .unwrap();
    }

    #[test]
    fn canonical_sans_normalizes_ips() {
        assert_eq!(
            canonical_sans(&[
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "host.test".into()
            ]),
            vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "host.test".to_string()
            ]
        );
    }
}
