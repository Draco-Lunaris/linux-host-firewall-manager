use sqlx::PgPool;

pub struct CertAuthority {
    pub ca_base: String,
}

#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub ca_root_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

impl CertAuthority {
    pub fn init(ca_base: String, _pool: &PgPool) -> Self {
        std::fs::create_dir_all(&ca_base).ok();
        Self { ca_base }
    }

    pub async fn issue_client_cert(
        &self,
        _host_id: i64,
        _fqdn: &str,
        _ip: &str,
        _pool: &PgPool,
    ) -> Result<IssuedCert, crate::error::CertError> {
        Err(crate::error::CertError::NotImplemented)
    }

    pub async fn generate_crl(&self, _pool: &PgPool) -> Result<String, crate::error::CertError> {
        Err(crate::error::CertError::NotImplemented)
    }
}
