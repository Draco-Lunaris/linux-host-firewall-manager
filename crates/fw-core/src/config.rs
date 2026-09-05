use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub worker: WorkerConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Port for the agent-facing mTLS API (mandatory client cert). The human UI
    /// stays on `port` (443) with server-side TLS only.
    #[serde(default = "default_agent_port")]
    pub agent_port: u16,
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
}

fn default_static_dir() -> String {
    "/usr/share/firewall-manager/frontend".to_string()
}

fn default_agent_port() -> u16 {
    8443
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    pub jwt_signing_key_path: String,
    pub jwt_verify_key_path: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_web_tls_cert_path")]
    pub web_tls_cert_path: String,
    #[serde(default = "default_web_tls_key_path")]
    pub web_tls_key_path: String,
    /// CA-signed server cert/key for the agent mTLS listener (8443). The manager
    /// issues it from its own CA on first start; agents validate it against the
    /// CA cert they pin, which the self-signed web cert does not chain to.
    #[serde(default = "default_agent_tls_cert_path")]
    pub agent_tls_cert_path: String,
    #[serde(default = "default_agent_tls_key_path")]
    pub agent_tls_key_path: String,
    /// SANs agents use to reach the manager (DNS names or IPs), baked into the
    /// agent-listener cert. An empty list disables the agent mTLS listener.
    #[serde(default = "default_agent_tls_sans")]
    pub agent_tls_sans: Vec<String>,
    /// Optional upstream sub-CA (intermediate) chain to import: the chain file
    /// holds the sub-CA cert followed by its upstream chain (root last), the
    /// key file holds the sub-CA's private key. When both files exist the
    /// sub-CA becomes the issuing CA (agent certs, listener cert, CRLs) and
    /// the self-generated root stays as a verification anchor for already-
    /// enrolled agents. Leave the paths absent/unset to use the self-root.
    #[serde(default = "default_ca_issuing_chain_path")]
    pub ca_issuing_chain_path: String,
    #[serde(default = "default_ca_issuing_key_path")]
    pub ca_issuing_key_path: String,
}

fn default_web_tls_cert_path() -> String {
    "/etc/firewall-manager/tls/cert.pem".to_string()
}

fn default_web_tls_key_path() -> String {
    "/etc/firewall-manager/tls/key.pem".to_string()
}

fn default_agent_tls_cert_path() -> String {
    "/etc/firewall-manager/tls/agent-cert.pem".to_string()
}

fn default_agent_tls_key_path() -> String {
    "/etc/firewall-manager/tls/agent-key.pem".to_string()
}

fn default_agent_tls_sans() -> Vec<String> {
    vec!["localhost".to_string(), "127.0.0.1".to_string()]
}

fn default_ca_issuing_chain_path() -> String {
    "/etc/firewall-manager/ca/issuing/chain.pem".to_string()
}

fn default_ca_issuing_key_path() -> String {
    "/etc/firewall-manager/ca/issuing/key.pem".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_health_poll")]
    pub health_poll_interval_secs: u64,
    #[serde(default = "default_drift_poll")]
    pub drift_poll_interval_secs: u64,
}

fn default_health_poll() -> u64 {
    300
}
fn default_drift_poll() -> u64 {
    900
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            health_poll_interval_secs: default_health_poll(),
            drift_poll_interval_secs: default_drift_poll(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RateLimitConfig {
    #[serde(default = "default_enrollment_burst")]
    pub enrollment_burst: u32,
    #[serde(default = "default_auth_burst")]
    pub auth_burst: u32,
    #[serde(default = "default_api_burst")]
    pub api_burst: u32,
}

fn default_enrollment_burst() -> u32 {
    3
}
fn default_auth_burst() -> u32 {
    10
}
fn default_api_burst() -> u32 {
    30
}

impl AppConfig {
    pub fn load() -> Result<Self, crate::error::AppError> {
        let config_path = std::env::var("FIREWALL_MANAGER_CONFIG")
            .unwrap_or_else(|_| "/etc/firewall-manager/config.toml".to_string());
        let builder = config::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .add_source(config::Environment::with_prefix("FIREWALL_MANAGER"));
        builder
            .build()
            .and_then(|c| c.try_deserialize::<AppConfig>())
            .map_err(|e| crate::error::AppError::Config(e.to_string()))
    }
}
