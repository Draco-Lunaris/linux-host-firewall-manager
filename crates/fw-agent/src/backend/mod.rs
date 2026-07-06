use async_trait::async_trait;
use fw_core::models::FirewallRule;

#[async_trait]
pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn compile(&self, rules: &[FirewallRule]) -> Result<CompiledRules, BackendError>;
    async fn apply(&self, compiled: &CompiledRules) -> Result<ApplyResult, BackendError>;
    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError>;
    async fn reset(&self) -> Result<(), BackendError>;
    async fn status(&self) -> Result<BackendStatus, BackendError>;
}

#[derive(Debug, Clone)]
pub struct CompiledRules {
    pub commands: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub applied: u32,
    pub failed: u32,
    pub snapshot_hash: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NormalizedSnapshot {
    pub rules: Vec<String>,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub active: bool,
    pub default_policy_in: String,
    pub default_policy_out: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("not installed")]
    NotInstalled,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn detect() -> Option<Box<dyn FirewallBackend>> {
    if which("ufw") {
        Some(Box::new(UfwBackend))
    } else if which("firewall-cmd") {
        Some(Box::new(FirewalldBackend))
    } else {
        None
    }
}

fn which(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub struct UfwBackend;
pub struct FirewalldBackend;

#[async_trait]
impl FirewallBackend for UfwBackend {
    fn name(&self) -> &'static str {
        "ufw"
    }
    async fn compile(&self, _rules: &[FirewallRule]) -> Result<CompiledRules, BackendError> {
        Ok(CompiledRules { commands: vec![] })
    }
    async fn apply(&self, _compiled: &CompiledRules) -> Result<ApplyResult, BackendError> {
        Ok(ApplyResult {
            applied: 0,
            failed: 0,
            snapshot_hash: String::new(),
            error: None,
        })
    }
    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError> {
        Ok(NormalizedSnapshot {
            rules: vec![],
            hash: String::new(),
        })
    }
    async fn reset(&self) -> Result<(), BackendError> {
        Ok(())
    }
    async fn status(&self) -> Result<BackendStatus, BackendError> {
        Ok(BackendStatus {
            active: false,
            default_policy_in: "deny".into(),
            default_policy_out: "allow".into(),
        })
    }
}

#[async_trait]
impl FirewallBackend for FirewalldBackend {
    fn name(&self) -> &'static str {
        "firewalld"
    }
    async fn compile(&self, _rules: &[FirewallRule]) -> Result<CompiledRules, BackendError> {
        Ok(CompiledRules { commands: vec![] })
    }
    async fn apply(&self, _compiled: &CompiledRules) -> Result<ApplyResult, BackendError> {
        Ok(ApplyResult {
            applied: 0,
            failed: 0,
            snapshot_hash: String::new(),
            error: None,
        })
    }
    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError> {
        Ok(NormalizedSnapshot {
            rules: vec![],
            hash: String::new(),
        })
    }
    async fn reset(&self) -> Result<(), BackendError> {
        Ok(())
    }
    async fn status(&self) -> Result<BackendStatus, BackendError> {
        Ok(BackendStatus {
            active: false,
            default_policy_in: "deny".into(),
            default_policy_out: "allow".into(),
        })
    }
}
