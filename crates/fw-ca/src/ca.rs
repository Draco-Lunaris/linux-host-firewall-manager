//! Internal Certificate Authority for the Firewall Manager.
//!
//! The manager always generates and persists its own root CA (`ca.pem` /
//! `ca.key.pem` under `ca_base`); on restart the key is loaded and the signing
//! identity is reconstructed from the same key + subject DN, so every leaf cert
//! chains to the persisted PEM that agents pin at enrollment.
//!
//! Optionally, the operator imports an **upstream sub-CA** (intermediate cert
//! chain + signing key, via config paths — see [`CertAuthority::with_issuing_ca`]).
//! The sub-CA then becomes the *issuing* CA: agent certs, the agent-listener
//! cert, and CRLs are signed with its key, and its full chain is what agents
//! pin. The self-generated root remains a verification anchor so
//! already-enrolled agents keep checking in — no re-enrollment needed. This is
//! how a two-tier chain is supported without the manager operating an internal
//! two-tier design.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, PublicKeyData, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use sqlx::{PgPool, Row};
use std::path::Path;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The on-disk lifetime of the CA cert (long; the manager is the trust root).
const CA_VALIDITY_YEARS: i64 = 10;
/// The lifetime of an agent (host) cert issued from this CA.
const HOST_CERT_VALIDITY_YEARS: i64 = 1;
/// The lifetime of a server cert issued for the manager's own listeners.
const SERVER_CERT_VALIDITY_YEARS: i64 = 1;
/// The subject CN of the self-generated root — the issuer identity when no
/// upstream sub-CA is imported.
const ROOT_SUBJECT_CN: &str = "Firewall Manager Root CA";

/// How long a generated CRL stays fresh (`next_update`). Consumers should
/// re-fetch at least this often; the CRL is regenerated on demand at each
/// startup and on each revocation.
const CRL_NEXT_UPDATE_HOURS: i64 = 24;

pub struct CertAuthority {
    /// Filesystem base for ca.pem / ca.key.pem.
    ca_base: String,
    /// The self-generated root: reconstruction of the signing identity each
    /// start (same key + subject DN ⇒ leaf certs chain to the persisted PEM).
    /// Verification anchor for every cert issued before an upstream sub-CA was
    /// imported, and the issuing CA itself when no sub-CA is configured.
    root: Issuer<'static, KeyPair>,
    /// The persisted root cert PEM (stable across restarts).
    root_cert_pem: String,
    /// Imported upstream sub-CA (None = the self-root issues everything).
    issuing: Option<IssuingCa>,
}

/// An upstream sub-CA (intermediate cert chain + signing key) imported by the
/// operator via config paths. Once loaded it becomes the issuing CA: agent
/// certs and the agent-listener cert are signed with its key, and its chain is
/// what agents pin. The self-generated root remains a verification anchor so
/// already-enrolled agents keep working.
struct IssuingCa {
    issuer: Issuer<'static, KeyPair>,
    /// The chain as provided (sub-CA cert first, upstream root last). Delivered
    /// to agents in `ca_chain` and used as verification anchors.
    chain_pems: Vec<String>,
    /// Serial (hex) of the sub-CA cert itself — recorded on leaf rows it issues
    /// so CRLs can be grouped per issuing CA.
    serial_hex: String,
    /// Subject CN of the sub-CA cert — the issuer identity the agent-listener
    /// cert must carry; a mismatch at startup triggers a re-issue.
    subject_cn: String,
}

#[derive(Debug, Clone)]
pub struct SignedCert {
    pub cert_pem: String,
    /// The issued cert's x509 serial, hex-encoded (lowercase, no prefix). The
    /// serial is chosen here (not by rcgen) so the issuer can persist it and
    /// later name it in the CRL.
    pub serial_hex: String,
    /// CA chain to ship to the agent (the issuing chain — the imported sub-CA
    /// chain when one is configured, otherwise the self-generated root).
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

        // Reconstruct the signing identity from the (loaded or freshly generated)
        // key. Same key + same subject DN => leaf certs chain to the persisted
        // ca_cert_pem (the authoritative PEM agents pin; the reconstructed
        // self-signature is never served).
        let root = Issuer::new(Self::build_ca_params(), ca_key);

        if first_run {
            persist_root_cert_row(pool, &ca_cert_pem).await?;
        }

        Ok(Self {
            ca_base,
            root,
            root_cert_pem: ca_cert_pem,
            issuing: None,
        })
    }

    /// Load an upstream sub-CA (intermediate) from config paths. The chain file
    /// may hold the sub-CA cert followed by its upstream chain (root last); the
    /// key file holds the sub-CA's private key. The sub-CA becomes the issuing
    /// CA (agent certs, listener cert, CRLs); the self-root stays a verification
    /// anchor so already-enrolled agents keep checking in.
    ///
    /// Validates before accepting: the chain parses, the first cert is a CA
    /// whose key usage allows keyCertSign **and cRLSign** (revocation for
    /// sub-CA-issued certs depends on signing CRLs with this key), and the
    /// key's public key matches the first cert's SubjectPublicKeyInfo.
    pub fn with_issuing_ca(
        mut self,
        chain_path: &str,
        key_path: &str,
    ) -> Result<Self, crate::error::CertError> {
        let chain_pem = std::fs::read_to_string(chain_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| crate::error::CertError::Rcgen(format!("issuing CA key: {e}")))?;

        let chain_pems = split_pem_chain(&chain_pem);
        let sub_cert_pem = chain_pems.first().ok_or_else(|| {
            crate::error::CertError::Rcgen(format!("no certificate in {chain_path}"))
        })?;
        let sub_cert_der = pem_to_der(sub_cert_pem)?;
        let (_rem, sub_cert) = x509_parser::parse_x509_certificate(&sub_cert_der)
            .map_err(|e| crate::error::CertError::Rcgen(format!("issuing CA cert: {e}")))?;

        if !sub_cert.is_ca() {
            return Err(crate::error::CertError::Rcgen(
                "issuing CA cert is not a CA (basicConstraints CA:true missing)".to_string(),
            ));
        }
        let usage = sub_cert.key_usage();
        let usage = usage.ok().flatten().map(|ext| *ext.value);
        let usage = usage.ok_or_else(|| {
            crate::error::CertError::Rcgen(
                "issuing CA cert has no keyUsage extension — cannot sign certs".to_string(),
            )
        })?;
        if !usage.key_cert_sign() {
            return Err(crate::error::CertError::Rcgen(
                "issuing CA cert keyUsage lacks keyCertSign — cannot sign agent certs".to_string(),
            ));
        }
        if !usage.crl_sign() {
            return Err(crate::error::CertError::Rcgen(
                "issuing CA cert keyUsage lacks cRLSign — CRL revocation requires it; \
                 ask the upstream CA for a sub-CA with cRLSign"
                    .to_string(),
            ));
        }
        // Proof of possession: the provided key's SPKI must equal the cert's.
        if key.subject_public_key_info() != sub_cert.tbs_certificate.subject_pki.raw {
            return Err(crate::error::CertError::Rcgen(
                "issuing CA key does not match the sub-CA certificate".to_string(),
            ));
        }

        let serial_hex = hex::encode(sub_cert.raw_serial());
        let subject_cn = sub_cert
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(String::from))
            .unwrap_or_default();
        let issuer = Issuer::from_ca_cert_pem(sub_cert_pem, key)
            .map_err(|e| crate::error::CertError::Rcgen(format!("issuing CA: {e}")))?;

        self.issuing = Some(IssuingCa {
            issuer,
            chain_pems,
            serial_hex,
            subject_cn,
        });
        Ok(self)
    }

    /// The CA params used both for first-time generation and for reconstructing
    /// the signing identity on restart (must be identical across runs).
    fn build_ca_params() -> CertificateParams {
        let mut params =
            CertificateParams::new(Vec::new()).expect("empty SAN list is valid for a CA cert");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, ROOT_SUBJECT_CN);
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

    /// The issuing identity: the imported sub-CA when present, else the
    /// self-generated root.
    fn issuer(&self) -> &Issuer<'static, KeyPair> {
        self.issuing
            .as_ref()
            .map(|ca| &ca.issuer)
            .unwrap_or(&self.root)
    }

    /// The serial (hex) of the current issuing CA, recorded on issued leaf
    /// rows so CRLs group per issuer. Empty (stored as NULL) when the
    /// self-root is issuing — CRL grouping treats NULL as root-issued.
    pub fn issuing_serial_hex(&self) -> &str {
        match &self.issuing {
            Some(ca) => &ca.serial_hex,
            None => "",
        }
    }

    /// The CA chain agents pin at enrollment: the full imported chain when a
    /// sub-CA is configured (sub-CA first, upstream root last), else the
    /// self-generated root.
    pub fn ca_chain_for_agents(&self) -> Vec<String> {
        match &self.issuing {
            Some(ca) => ca.chain_pems.clone(),
            None => vec![self.root_cert_pem.clone()],
        }
    }

    /// All verification anchors for the agent mTLS client verifier: the
    /// self-generated root (legacy certs) plus the imported chain when an
    /// upstream sub-CA is in use. Both are trusted.
    pub fn verification_anchors(&self) -> Vec<String> {
        let mut anchors = vec![self.root_cert_pem.clone()];
        if let Some(ca) = &self.issuing {
            anchors.extend(ca.chain_pems.iter().cloned());
        }
        anchors
    }

    /// The imported sub-CA chain, for the CA info endpoint. `None` when the
    /// self-root is the issuing CA.
    pub fn issuing_chain_pems(&self) -> Option<&[String]> {
        self.issuing.as_ref().map(|ca| ca.chain_pems.as_slice())
    }

    /// The subject CN of the current issuing CA ("Firewall Manager Root CA"
    /// when no sub-CA is imported). The agent-listener cert's issuer must
    /// match; a mismatch at startup triggers a re-issue under the new CA.
    pub fn issuing_subject_cn(&self) -> &str {
        match &self.issuing {
            Some(ca) => &ca.subject_cn,
            None => ROOT_SUBJECT_CN,
        }
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

        // Explicit serial: the issuer must know the serial it issued so it can
        // persist it and revoke the cert by serial later (CRL). A UUID's 16
        // bytes are random and collision-impractical, matching x509 serial
        // practice (≤20 octets, positive).
        let serial = Uuid::new_v4();
        csr.params.serial_number = Some(SerialNumber::from_slice(serial.as_bytes()));

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
            .signed_by(self.issuer())
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
        let cert_pem = cert.pem();

        Ok(SignedCert {
            cert_pem,
            serial_hex: hex::encode(serial.as_bytes()),
            ca_chain: self.ca_chain_for_agents(),
            crl_pem: None,
        })
    }

    /// Issue a CA-signed server cert for one of the manager's own listeners.
    ///
    /// The manager generates a fresh keypair and signs a leaf cert with the
    /// requested SANs (each entry is interpreted as an IP address if it parses
    /// as one, otherwise as a DNS name) and the ServerAuth EKU. The agent pull
    /// client validates the manager's server cert against the chain it pins,
    /// so any listener the agents talk to must serve a cert from the issuing
    /// CA — the self-signed web cert does not chain to it.
    pub fn issue_server_cert(
        &self,
        sans: &[String],
    ) -> Result<ServerCert, crate::error::CertError> {
        let key = KeyPair::generate().map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        // DNS names go through CertificateParams::new; IP SANs are appended
        // (rcgen 0.14 keeps the Ia5String type private, so DNS names can only
        // enter via the params constructor).
        let mut dns: Vec<String> = Vec::new();
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for san in sans {
            match san.parse::<std::net::IpAddr>() {
                Ok(ip) => ips.push(ip),
                Err(_) => dns.push(san.clone()),
            }
        }
        let mut params = CertificateParams::new(dns)
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
        for ip in ips {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
        }
        params
            .distinguished_name
            .push(DnType::CommonName, "Firewall Manager Agent API");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Firewall Manager");
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
            .signed_by(&key, self.issuer())
            .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;

        Ok(ServerCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// Generate CRLs for the revoked certs in the `certificates` table.
    ///
    /// Bundles every cert with `status = 'revoked'` that has not yet naturally
    /// expired (pruning naturally-expired certs keeps the CRL small) into
    /// X.509 v2 CRLs. Revocations are grouped by issuing CA via the row's
    /// `issuer_serial`: one CRL per issuing CA (the self-root for legacy rows,
    /// the imported sub-CA for the rest), because a CRL is only meaningful
    /// when signed by the CA that issued the certs it names. The manager's
    /// mTLS client verifier consumes these to reject revoked host certs at
    /// the TLS handshake.
    ///
    /// Generated on demand (startup + after each revocation): at LHFM's scale
    /// this is a small query and KB-range CRLs, so no caching is warranted.
    /// Returns one PEM per non-empty group; a single CRL in the common case.
    pub async fn generate_crls(&self, db: &PgPool) -> Result<Vec<String>, crate::error::CertError> {
        let rows = sqlx::query(
            "SELECT serial_number, revoked_at, issuer_serial \
             FROM certificates \
             WHERE status = 'revoked'::cert_status \
               AND revoked_at IS NOT NULL \
               AND expires_at > NOW() \
             ORDER BY revoked_at ASC",
        )
        .fetch_all(db)
        .await?;

        let issuing_group = self.issuing.as_ref().map(|ca| ca.serial_hex.as_str());
        let mut root_revoked = Vec::new();
        let mut issuing_revoked = Vec::new();
        for row in &rows {
            let serial_hex: String = row.try_get("serial_number")?;
            let revoked_at: chrono::DateTime<chrono::Utc> = row.try_get("revoked_at")?;
            let issuer_serial: Option<String> = row.try_get("issuer_serial")?;

            // serial_number is stored hex-encoded (see sign_csr).
            let serial_bytes = hex::decode(serial_hex.trim())
                .map_err(|e| crate::error::CertError::Rcgen(format!("serial_number hex: {e}")))?;
            let revocation_time = OffsetDateTime::from_unix_timestamp(revoked_at.timestamp())
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
            let params = RevokedCertParams {
                serial_number: SerialNumber::from_slice(&serial_bytes),
                revocation_time,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            };

            // An imported sub-CA is active: rows it issued group under it. NULL
            // (pre-issuer-tracking rows), the root's own serial, and any other
            // value are legacy/root-issued and group under the root CRL.
            let in_issuing_group = match issuing_group {
                Some(serial) => issuer_serial.as_deref() == Some(serial),
                None => false,
            };
            if in_issuing_group {
                issuing_revoked.push(params);
            } else {
                root_revoked.push(params);
            }
        }

        let now = OffsetDateTime::now_utc();
        let mut crls = Vec::new();
        for (revoked_certs, issuer) in [
            (root_revoked, &self.root),
            (
                issuing_revoked,
                self.issuing
                    .as_ref()
                    .map(|ca| &ca.issuer)
                    .unwrap_or(&self.root),
            ),
        ] {
            if revoked_certs.is_empty() {
                continue;
            }
            let params = CertificateRevocationListParams {
                this_update: now,
                next_update: now
                    .checked_add(Duration::hours(CRL_NEXT_UPDATE_HOURS))
                    .unwrap_or(now),
                crl_number: SerialNumber::from_slice(&now.unix_timestamp().to_be_bytes()),
                issuing_distribution_point: None,
                revoked_certs,
                key_identifier_method: KeyIdMethod::Sha256,
            };
            let crl = params
                .signed_by(issuer)
                .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
            let crl_pem = crl
                .pem()
                .map_err(|e| crate::error::CertError::Rcgen(e.to_string()))?;
            crls.push(crl_pem);
        }
        Ok(crls)
    }

    /// The pinned root CA cert PEM (legacy verification anchor).
    pub fn root_cert_pem(&self) -> &str {
        &self.root_cert_pem
    }

    /// Filesystem base (kept for future CRL/distribution-point paths).
    pub fn ca_base(&self) -> &str {
        &self.ca_base
    }
}

/// Split a PEM bundle into individual PEM blocks (certificates of a chain).
fn split_pem_chain(bundle: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in bundle.lines() {
        current.push_str(line);
        current.push('\n');
        if line.contains("-----END CERTIFICATE-----") {
            blocks.push(std::mem::take(&mut current));
        }
    }
    blocks
}

/// Decode a single PEM block to its DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, crate::error::CertError> {
    use base64::Engine as _;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| crate::error::CertError::Rcgen(format!("invalid PEM base64: {e}")))
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
