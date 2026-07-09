//! mTLS certificate loading for the agent server.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Cursor;
use std::path::Path;

pub struct AgentCerts {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub ca_cert: CertificateDer<'static>,
}

pub fn load_certs(cert_dir: &str) -> Result<AgentCerts> {
    let ca_path = format!("{}/ca.pem", cert_dir);
    let cert_path = format!("{}/server.pem", cert_dir);
    let key_path = format!("{}/server.key.pem", cert_dir);

    for (path, desc) in [
        (&ca_path, "CA cert"),
        (&cert_path, "server cert"),
        (&key_path, "server key"),
    ] {
        if !Path::new(path).exists() {
            anyhow::bail!(
                "{} not found at {} — run `fw-agent enroll` first",
                desc,
                path
            );
        }
    }

    // Load CA
    let ca_pem = std::fs::read(&ca_path).context("Failed to read CA cert")?;
    let mut ca_cursor = Cursor::new(&ca_pem[..]);
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_cursor)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse CA certs")?;
    let ca_cert = ca_certs
        .into_iter()
        .next()
        .context("No certificate found in CA PEM")?;

    // Load server cert chain
    let cert_pem = std::fs::read(&cert_path).context("Failed to read server cert")?;
    let mut cert_cursor = Cursor::new(&cert_pem[..]);
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse server cert chain")?;

    // Load private key
    let key_pem = std::fs::read(&key_path).context("Failed to read server key")?;
    let mut key_cursor = Cursor::new(&key_pem[..]);
    let private_key = rustls_pemfile::private_key(&mut key_cursor)
        .context("Failed to parse private key")?
        .context("No private key found in key PEM")?;

    Ok(AgentCerts {
        cert_chain,
        private_key,
        ca_cert,
    })
}
