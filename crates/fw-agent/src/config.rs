use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub manager_url: String,
    pub fqdn: String,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default = "default_port")]
    pub listen_port: u16,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    #[serde(default)]
    pub safe_mode_enabled: bool,
    #[serde(default = "default_safe_mode_timeout")]
    pub safe_mode_timeout_secs: u64,
    #[serde(default)]
    pub protected_cidrs: Vec<String>,
    #[serde(default)]
    pub pull: PullConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PullConfig {
    #[serde(default = "default_check_in_interval")]
    pub check_in_interval_secs: u32,
    #[serde(default)]
    pub manager_check_in_url: String,
    #[serde(default = "default_push_enabled")]
    pub push_enabled: bool,
    #[serde(default)]
    pub config_version: i32,
}

fn default_check_in_interval() -> u32 {
    900
}

fn default_push_enabled() -> bool {
    true
}

fn default_port() -> u16 {
    12443
}
fn default_cert_dir() -> String {
    "/etc/firewall-agent/certs".to_string()
}
fn default_config_dir() -> String {
    "/etc/firewall-agent".to_string()
}
fn default_log_dir() -> String {
    "/var/log/firewall-agent".to_string()
}
fn default_safe_mode_timeout() -> u64 {
    1800
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: String::new(),
            fqdn: String::new(),
            host_id: None,
            listen_port: default_port(),
            cert_dir: default_cert_dir(),
            config_dir: default_config_dir(),
            log_dir: default_log_dir(),
            safe_mode_enabled: false,
            safe_mode_timeout_secs: default_safe_mode_timeout(),
            protected_cidrs: Vec::new(),
            pull: PullConfig {
                check_in_interval_secs: default_check_in_interval(),
                manager_check_in_url: String::new(),
                push_enabled: default_push_enabled(),
                config_version: 0,
            },
        }
    }
}

impl AgentConfig {
    pub fn config_path() -> String {
        "/etc/firewall-agent/config.toml".to_string()
    }

    pub fn load() -> Option<Self> {
        let path = Self::config_path();
        if !std::path::Path::new(&path).exists() {
            return None;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        toml::from_str(&content).ok()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = Self::config_path();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string(self).unwrap_or_default();
        std::fs::write(&path, content)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}
