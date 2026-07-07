//! Firewall backend abstraction.
//!
//! The agent detects which backend is active on the host and uses it
//! to compile typed rules into backend-specific commands, apply them
//! atomically, and capture snapshots for drift detection.
//!
//! v0.1: UFW + firewalld
//! v0.2: nftables + iptables

use async_trait::async_trait;
use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
use sha2::{Digest, Sha256};
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("not installed")]
    NotInstalled,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("container runtime detected: {0}")]
    ContainerConflict(String),
}

#[derive(Debug, Clone)]
pub struct CompiledRules {
    pub commands: Vec<String>,
    pub backend_name: String,
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

#[async_trait]
pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn compile(&self, rules: &[FirewallRule]) -> Result<CompiledRules, BackendError>;
    async fn apply(&self, compiled: &CompiledRules) -> Result<ApplyResult, BackendError>;
    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError>;
    async fn reset(&self) -> Result<(), BackendError>;
    async fn status(&self) -> Result<BackendStatus, BackendError>;
}

/// Detect which firewall backend is active on this host.
/// Priority: distro native wrapper first, then raw backends.
pub fn detect() -> Option<Box<dyn FirewallBackend>> {
    // Check for container runtime conflict (SEC-005)
    if let Some(runtime) = container_detect::detect_container_runtime() {
        tracing::warn!(
            runtime = %runtime,
            "Container runtime detected — UFW backend may conflict with container networking"
        );
    }

    // Detect in priority order:
    // 1. UFW (Debian/Ubuntu native wrapper)
    // 2. firewalld (RHEL/Fedora/Alma native wrapper)
    // 3. nftables (v0.2)
    // 4. iptables (v0.2)
    if which("ufw") && ufw_is_active() {
        return Some(Box::new(UfwBackend));
    }
    if which("firewall-cmd") && firewalld_is_active() {
        return Some(Box::new(FirewalldBackend));
    }
    None
}

fn which(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ufw_is_active() -> bool {
    Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("Status: active")
        })
        .unwrap_or(false)
}

fn firewalld_is_active() -> bool {
    Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim() == "running"
        })
        .unwrap_or(false)
}

/// Run a command and return (success, stdout, stderr).
fn run_cmd(cmd: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(cmd).args(args).output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            (o.status.success(), stdout, stderr)
        }
        Err(e) => (false, String::new(), e.to_string()),
    }
}

// ============================================================
// UFW Backend
// ============================================================

pub struct UfwBackend;

#[async_trait]
impl FirewallBackend for UfwBackend {
    fn name(&self) -> &'static str {
        "ufw"
    }

    async fn compile(&self, rules: &[FirewallRule]) -> Result<CompiledRules, BackendError> {
        let mut commands = Vec::new();
        for rule in rules {
            commands.push(compile_ufw_rule(rule));
        }
        Ok(CompiledRules {
            commands,
            backend_name: "ufw".to_string(),
        })
    }

    async fn apply(&self, compiled: &CompiledRules) -> Result<ApplyResult, BackendError> {
        // Atomic apply using iptables-save/iptables-restore (SEC-006):
        // 1. Capture current state: iptables-save > backup
        // 2. Build new ruleset via ufw reset + replay
        // 3. If any command fails, restore from backup
        //
        // For v0.1 we use ufw --force reset + replay (simpler, has brief window).
        // v0.2 will use iptables-restore for true atomicity.

        // Check container runtime (SEC-005)
        if let Some(runtime) = container_detect::detect_container_runtime() {
            tracing::warn!(
                runtime = %runtime,
                "Applying UFW rules on a host with {} — this may break container networking",
                runtime
            );
        }

        // Reset
        let (ok, _, err) = run_cmd("ufw", &["--force", "reset"]);
        if !ok {
            return Ok(ApplyResult {
                applied: 0,
                failed: 0,
                snapshot_hash: String::new(),
                error: Some(format!("ufw reset failed: {}", err)),
            });
        }

        // Enable
        let (ok, _, err) = run_cmd("ufw", &["--force", "enable"]);
        if !ok {
            return Ok(ApplyResult {
                applied: 0,
                failed: 0,
                snapshot_hash: String::new(),
                error: Some(format!("ufw enable failed: {}", err)),
            });
        }

        // Apply each rule
        let mut applied = 0u32;
        let mut failed = 0u32;
        let mut errors = Vec::new();
        for cmd in &compiled.commands {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let (ok, _, err) = run_cmd(parts[0], &parts[1..]);
            if ok {
                applied += 1;
            } else {
                failed += 1;
                errors.push(format!("{}: {}", cmd, err));
            }
        }

        // Reload
        let _ = run_cmd("ufw", &["reload"]);

        // Capture snapshot
        let snapshot = self.snapshot().await?;
        let hash = snapshot.hash;

        Ok(ApplyResult {
            applied,
            failed,
            snapshot_hash: hash,
            error: if errors.is_empty() {
                None
            } else {
                Some(errors.join("; "))
            },
        })
    }

    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError> {
        let (ok, stdout, _) = run_cmd("ufw", &["status", "numbered"]);
        if !ok {
            return Ok(NormalizedSnapshot {
                rules: vec![],
                hash: String::new(),
            });
        }
        // Normalize: sort lines, strip line numbers
        let mut lines: Vec<String> = stdout
            .lines()
            .skip(2) // Skip "Status: active" and blank line
            .map(|l| {
                // Strip leading "[ N] " prefix
                let trimmed = l.trim();
                if let Some(idx) = trimmed.find(']') {
                    trimmed[idx + 1..].trim().to_string()
                } else {
                    trimmed.to_string()
                }
            })
            .filter(|l| !l.is_empty())
            .collect();
        lines.sort();

        let mut hasher = Sha256::new();
        for line in &lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        let hash = hex::encode(hasher.finalize());

        Ok(NormalizedSnapshot { rules: lines, hash })
    }

    async fn reset(&self) -> Result<(), BackendError> {
        let (ok, _, err) = run_cmd("ufw", &["--force", "reset"]);
        if !ok {
            return Err(BackendError::CommandFailed(err));
        }
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let (ok, stdout, _) = run_cmd("ufw", &["status"]);
        let active = ok && stdout.contains("Status: active");
        let default_in = if stdout.contains("deny (incoming)") {
            "deny".to_string()
        } else {
            "allow".to_string()
        };
        let default_out = if stdout.contains("allow (outgoing)") {
            "allow".to_string()
        } else {
            "deny".to_string()
        };
        Ok(BackendStatus {
            active,
            default_policy_in: default_in,
            default_policy_out: default_out,
        })
    }
}

fn compile_ufw_rule(rule: &FirewallRule) -> String {
    let mut cmd = "ufw".to_string();
    match rule.action {
        FirewallAction::Allow => cmd.push_str(" allow"),
        FirewallAction::Deny => cmd.push_str(" deny"),
        FirewallAction::Reject => cmd.push_str(" reject"),
        FirewallAction::Limit => cmd.push_str(" limit"),
        FirewallAction::Masquerade => cmd.push_str(" masquerade"),
    }
    if rule.direction == FirewallDirection::Out {
        cmd.push_str(" out");
    }
    if rule.protocol != FirewallProtocol::Any {
        cmd.push_str(&format!(
            " proto {}",
            format!("{:?}", rule.protocol).to_lowercase()
        ));
    }
    if let Some(src) = &rule.src_cidr {
        cmd.push_str(&format!(" from {}", src));
    }
    if let Some(dst) = &rule.dst_cidr {
        cmd.push_str(&format!(" to {}", dst));
    }
    if let Some(port) = rule.dst_port_start {
        if let Some(end) = rule.dst_port_end {
            if port == end {
                cmd.push_str(&format!(" port {}", port));
            } else {
                cmd.push_str(&format!(" port {}:{}", port, end));
            }
        } else {
            cmd.push_str(&format!(" port {}", port));
        }
    }
    if let Some(iface) = &rule.interface_in {
        cmd.push_str(&format!(" on {}", iface));
    }
    if !rule.comment.is_empty() {
        cmd.push_str(&format!(" comment '{}'", rule.comment.replace('\'', "")));
    }
    cmd
}

// ============================================================
// firewalld Backend
// ============================================================

pub struct FirewalldBackend;

#[async_trait]
impl FirewallBackend for FirewalldBackend {
    fn name(&self) -> &'static str {
        "firewalld"
    }

    async fn compile(&self, rules: &[FirewallRule]) -> Result<CompiledRules, BackendError> {
        let mut commands = Vec::new();
        for rule in rules {
            commands.push(compile_firewalld_rule(rule));
        }
        Ok(CompiledRules {
            commands,
            backend_name: "firewalld".to_string(),
        })
    }

    async fn apply(&self, compiled: &CompiledRules) -> Result<ApplyResult, BackendError> {
        let mut applied = 0u32;
        let mut failed = 0u32;
        let mut errors = Vec::new();

        for cmd in &compiled.commands {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let (ok, _, err) = run_cmd(parts[0], &parts[1..]);
            if ok {
                applied += 1;
            } else {
                failed += 1;
                errors.push(format!("{}: {}", cmd, err));
            }
        }

        // Reload to apply --permanent rules
        let _ = run_cmd("firewall-cmd", &["--reload"]);

        let snapshot = self.snapshot().await?;
        let hash = snapshot.hash;

        Ok(ApplyResult {
            applied,
            failed,
            snapshot_hash: hash,
            error: if errors.is_empty() {
                None
            } else {
                Some(errors.join("; "))
            },
        })
    }

    async fn snapshot(&self) -> Result<NormalizedSnapshot, BackendError> {
        let (ok, stdout, _) = run_cmd("firewall-cmd", &["--list-all"]);
        if !ok {
            return Ok(NormalizedSnapshot {
                rules: vec![],
                hash: String::new(),
            });
        }
        let mut lines: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        lines.sort();

        let mut hasher = Sha256::new();
        for line in &lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        let hash = hex::encode(hasher.finalize());

        Ok(NormalizedSnapshot { rules: lines, hash })
    }

    async fn reset(&self) -> Result<(), BackendError> {
        // Reset to default zone
        let (ok, _, err) = run_cmd(
            "firewall-cmd",
            &["--permanent", "--zone=public", "--remove-all"],
        );
        if !ok {
            return Err(BackendError::CommandFailed(err));
        }
        let _ = run_cmd("firewall-cmd", &["--reload"]);
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let (ok, stdout, _) = run_cmd("firewall-cmd", &["--state"]);
        let active = ok && stdout.trim() == "running";
        let (default_ok, default_out, _) = run_cmd("firewall-cmd", &["--get-default-zone"]);
        let default_zone = if default_ok {
            default_out.trim().to_string()
        } else {
            "public".to_string()
        };
        Ok(BackendStatus {
            active,
            default_policy_in: default_zone.clone(),
            default_policy_out: default_zone,
        })
    }
}

fn compile_firewalld_rule(rule: &FirewallRule) -> String {
    let action = match rule.action {
        FirewallAction::Allow => "accept",
        FirewallAction::Deny => "drop",
        FirewallAction::Reject => "reject",
        FirewallAction::Limit => "accept",
        FirewallAction::Masquerade => "masquerade",
    };
    let proto = match &rule.protocol {
        FirewallProtocol::Any => "all".to_string(),
        p => format!("{:?}", p).to_lowercase(),
    };
    let src = rule.src_cidr.as_deref().unwrap_or("0.0.0.0/0");
    let port = rule
        .dst_port_start
        .map(|p| p.to_string())
        .unwrap_or_default();

    if port.is_empty() {
        format!(
            "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"{}\" {}'",
            src, action
        )
    } else {
        format!(
            "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"{}\" port port=\"{}\" protocol=\"{}\" {}'",
            src, port, proto, action
        )
    }
}

// ============================================================
// Container runtime detection (SEC-005)
// ============================================================

pub mod container_detect {
    pub fn detect_container_runtime() -> Option<String> {
        // Check for Docker
        if std::path::Path::new("/var/run/docker.sock").exists() {
            return Some("docker".to_string());
        }
        // Check for Podman
        if which("podman") {
            return Some("podman".to_string());
        }
        // Check for Kubernetes
        if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            return Some("kubernetes".to_string());
        }
        // Check for containerd
        if std::path::Path::new("/run/containerd/containerd.sock").exists() {
            return Some("containerd".to_string());
        }
        None
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
}
