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
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
}

fn default_static_dir() -> String {
    "/usr/share/firewall-manager/frontend".to_string()
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_agent_calls: usize,
    #[serde(default = "default_health_poll")]
    pub health_poll_interval_secs: u64,
    #[serde(default = "default_drift_poll")]
    pub drift_poll_interval_secs: u64,
}

fn default_max_concurrent() -> usize {
    64
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
            max_concurrent_agent_calls: default_max_concurrent(),
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
