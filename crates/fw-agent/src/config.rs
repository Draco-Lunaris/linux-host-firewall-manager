use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub manager_url: String,
    pub fqdn: String,
    pub host_id: Option<i64>,
    pub listen_port: u16,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: String::new(),
            fqdn: String::new(),
            host_id: None,
            listen_port: 12443,
        }
    }
}

pub fn load() -> Option<AgentConfig> {
    let path = "/etc/firewall-agent/config.toml";
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}
