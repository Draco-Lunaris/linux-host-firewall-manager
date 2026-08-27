//! Internal Certificate Authority for the Firewall Manager.
//!
//! Single-tier (v0.1): the manager holds one online root CA that directly signs
//! each agent's CSR. The two-tier offline-root + online-intermediate split
//! (SEC-001) is deferred to a hardening pass — it is operational hardening, not a
//! correctness requirement for per-host mTLS binding.
//!
//! The CA cert + key are generated on first start and persisted to `ca_base`
//! (`ca.pem` / `ca.key.pem`). On restart the key is loaded and the signing
//! `Certificate` is reconstructed by re-self-signing with the same key + subject;
//! because the subject DN and key are unchanged, every leaf cert chains to the
//! persisted CA cert PEM that agents pin at enrollment. The persisted CA cert PEM
//! is what is served to agents (stable across restarts).

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sqlx::PgPool;
use std::path::Path;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The on-disk lifetime of the CA cert (long; the manager is the trust root).
const CA_VALIDITY_YEARS: i64 = 10;
/// The lifetime of an agent (host) cert issued from this CA.
const HOST_CERT_VALIDITY_YEARS: i64 = 1;
/// The lifetime of a server cert issued for the manager's own listeners.
const SERVER_CERT_VALIDITY_YEARS: i64 = 1;

pub struct CertAuthority {
    /// Filesystem base for ca.pem / ca.key.pem.
    ca_base: String,
    /// The signing CA certificate (reconstructed each start from the persisted key).
    ca_cert: Certificate,
    /// The CA private key.
    ca_key: KeyPair,
    /// The persisted CA cert PEM, served to agents as the trust anchor (stable across restarts).
    ca_cert_pem: String,
}

#[derive(Debug, Clone)]
pub struct SignedCert {
    pub cert_pem: String,
    /// CA chain to ship to the agent (the pinned CA cert).
    pub ca_chain: Vec<String>,
    /// CRL PEM, if any (deferred — None for now).
    pub crl_pem: Option<String>,
}

/// A CA-signed server cert for the manager's own listeners, with its fresh key.
#[derive(Debug, Clone)]
pub struct ServerCert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertAuthority {
    /// Load the CA from disk, generating it on first run. Persists the root cert
    /// row in the `certificates` table on first generation.
    pub async fn init(ca_base: String, pool: &PgPool) -> Result<Self, crate::error::CertError> {
        std::fs::create_dir_all(&ca_base)?;
        let cert_path = format!("{}/ca.pem", ca_base);
        let key_path = format!("{}/ca.key.pem", ca_base);

        let (ca_key, ca_cert_pem, first_run) =
            if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
                let key_pem = std::fs::read_to_string(&key_path)?;
                let cert_pem = std::fs::read_to_string(&cert_path)?;
                let key = KeyPair::from_pem(&key_pem)
                    .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
                (key, cert_pem, false)
            } else {
                let key = KeyPair::generate()
                    .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
                let cert = Self::build_ca_params()
                    .self_signed(&key)
                    .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
                let cert_pem = cert.pem();
                // Persist before doing anything else; a lost key invalidates every issued cert.
                std::fs::write(&cert_path, &cert_pem)?;
                std::fs::write(&key_path, key.serialize_pem())?;
                restrict_key_permissions(&key_path);
                (key, cert_pem, true)
            };

        // Reconstruct the signing Certificate from the (loaded or freshly generated) key.
        // Same key + same subject DN => leaf certs chain to the persisted ca_cert_pem.
        let ca_cert = Self::build_ca_params()
            .self_signed(&ca_key)
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        if first_run {
            persist_root_cert_row(pool, &ca_cert_pem).await?;
        }

        Ok(Self {
            ca_base,
            ca_cert,
            ca_key,
            ca_cert_pem,
        })
    }

    /// The CA params used both for first-time generation and for reconstructing
    /// the signing Certificate on restart (must be identical across runs).
    fn build_ca_params() -> CertificateParams {
        let mut params =
            CertificateParams::new(Vec::new()).expect("empty SAN list is valid for a CA cert");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Firewall Manager Root CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Firewall Manager");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
        params.not_after = now
            .checked_add(Duration::days(365 * CA_VALIDITY_YEARS))
            .unwrap_or(now);
        params
    }

    /// Sign an agent CSR, overriding the subject CN to the assigned host_id.
    ///
    /// The manager — not the agent — decides the host identity: the agent's CSR
    /// carries its FQDN as CN, but the issued cert's CN is rewritten to the
    /// `host_id` UUID. The host_authz extractor reads this CN to bind the request
    /// to the host. The CSR signature is verified during parsing (proof of
    /// possession of the private key).
    pub fn sign_csr(
        &self,
        csr_pem: &str,
        host_id: Uuid,
    ) -> Result<SignedCert, crate::error::CertError> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        // Rewrite the subject so the cert identity is the manager-assigned host_id.
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host_id.to_string());
        dn.push(DnType::OrganizationName, "Firewall Manager Agent");
        csr.params.distinguished_name = dn;

        // The agent's key is used for both server (mTLS listener) and client
        // (check-in) roles in the pull model.
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        csr.params.use_authority_key_identifier_extension = true;

        let now = OffsetDateTime::now_utc();
        csr.params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
        csr.params.not_after = now
            .checked_add(Duration::days(365 * HOST_CERT_VALIDITY_YEARS))
            .unwrap_or(now);

        let cert = csr
            .signed_by(&self.ca_cert, &self.ca_key)
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
        let cert_pem = cert.pem();

        Ok(SignedCert {
            cert_pem,
            ca_chain: vec![self.ca_cert_pem.clone()],
            crl_pem: None,
        })
    }

    /// Issue a CA-signed server cert for one of the manager's own listeners.
    ///
    /// The manager generates a fresh keypair and signs a leaf cert with the
    /// requested SANs (each entry is interpreted as an IP address if it parses
    /// as one, otherwise as a DNS name) and the ServerAuth EKU. The agent pull
    /// client validates the manager's server cert against the CA cert it pins,
    /// so any listener the agents talk to must serve a cert from this CA —
    /// the self-signed web cert does not chain to it.
    pub fn issue_server_cert(
        &self,
        sans: &[String],
    ) -> Result<ServerCert, crate::error::CertError> {
        let key = KeyPair::generate().map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "Firewall Manager Agent API");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Firewall Manager");
        params.subject_alt_names = sans
            .iter()
            .map(|san| match san.parse::<std::net::IpAddr>() {
                Ok(ip) => Ok(rcgen::SanType::IpAddress(ip)),
                Err(_) => rcgen::Ia5String::try_from(san.as_str())
                    .map(rcgen::SanType::DnsName)
                    .map_err(|e| {
                        crate::error::CertError::Rcgen(format!("invalid DNS SAN {san:?}: {e}"))
                    }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let now = OffsetDateTime::now_utc();
        params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
        params.not_after = now
            .checked_add(Duration::days(365 * SERVER_CERT_VALIDITY_YEARS))
            .unwrap_or(now);

        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        Ok(ServerCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// The pinned CA cert PEM (trust anchor for the agent mTLS client verifier).
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Filesystem base (kept for future CRL/distribution-point paths).
    pub fn ca_base(&self) -> &str {
        &self.ca_base
    }
}

fn restrict_key_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

async fn persist_root_cert_row(
    pool: &PgPool,
    cert_pem: &str,
) -> Result<(), crate::error::CertError> {
    // Only insert if no active root row exists yet.
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM certificates WHERE ca_tier = 'root' AND status = 'active'",
    )
    .fetch_one(pool)
    .await?;
    if existing > 0 {
        return Ok(());
    }
    let serial = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO certificates (host_id, serial_number, common_name, status, issued_at, expires_at, cert_pem, ca_tier)
         VALUES (NULL, $1, 'Firewall Manager Root CA', 'active', NOW(), NOW() + ($2 || ' days')::interval, $3, 'root')",
    )
    .bind(&serial)
    .bind((365 * CA_VALIDITY_YEARS).to_string())
    .bind(cert_pem)
    .execute(pool)
    .await?;
    Ok(())
}
