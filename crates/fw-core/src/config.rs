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
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub ip_whitelist: Vec<String>,
    pub jwt_signing_key_path: String,
    pub jwt_verify_key_path: String,
    pub trusted_proxies: Vec<String>,
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    pub max_concurrent_agent_calls: usize,
    pub health_poll_interval_secs: u64,
    pub drift_poll_interval_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_agent_calls: 64,
            health_poll_interval_secs: 300,
            drift_poll_interval_secs: 900,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub enrollment_burst: u32,
    pub auth_burst: u32,
    pub api_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enrollment_burst: 3,
            auth_burst: 10,
            api_burst: 30,
        }
    }
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
