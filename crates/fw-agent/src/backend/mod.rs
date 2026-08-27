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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct CompiledRules {
    pub commands: Vec<String>,
}

/// Context the backend needs to compile a full apply: the policy-set default
/// policies (None = system default — don't touch that direction) and the
/// manager endpoint used to build the unremovable outbound "umbilical" allow
/// that keeps the agent's pull path alive under a default-deny-outgoing policy.
#[derive(Debug, Clone)]
pub struct ApplyContext {
    /// Manager IP literal (the agent normalizes the URL to an IP at enrollment
    /// so there is no DNS dependency at apply time).
    pub manager_ip: String,
    pub manager_port: u16,
    /// `allow`/`deny`/`reject` or None (system default — no `ufw default` call).
    pub default_input_policy: Option<String>,
    pub default_output_policy: Option<String>,
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
    /// Compile the policy rules into the ordered command list the backend runs
    /// after a reset. The `ApplyContext` carries the policy-set default
    /// policies and the manager endpoint so the backend can prepend the
    /// umbilical allow + `ufw default` calls before the policy rules.
    async fn compile(
        &self,
        rules: &[FirewallRule],
        ctx: &ApplyContext,
    ) -> Result<CompiledRules, BackendError>;
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

/// Run `ufw --force reset`, retrying when ufw aborts because its timestamped
/// backup from a previous reset already exists. ufw backs each rules file up as
/// `<name>.<YYYYMMDD_HHMMSS>` before clearing it and refuses to overwrite that
/// file — so two resets within the same second (two applies in a row, e.g. a
/// force-check-in right after a check-in) collide on the same backup names and
/// fail. ufw makes several such backups per reset (before/after/user, + .v6),
/// so the collision is cleared and the reset retried in a bounded loop.
/// Removing the collided auto-backup is safe: it is ufw's own throwaway
/// snapshot of the pre-reset state, not a referenced artifact.
fn ufw_force_reset() -> (bool, String, String) {
    let (mut ok, mut stdout, mut stderr) = run_cmd("ufw", &["--force", "reset"]);
    for _ in 0..8 {
        if ok {
            break;
        }
        let Some(backup) = collided_ufw_backup(&stderr) else {
            break;
        };
        tracing::warn!(backup, "removing stale ufw reset backup and retrying reset");
        if std::fs::remove_file(&backup).is_err() {
            break;
        }
        (ok, stdout, stderr) = run_cmd("ufw", &["--force", "reset"]);
    }
    (ok, stdout, stderr)
}

/// The backup path from a ufw reset collision error line, e.g.
/// `ERROR: '/etc/ufw/before.rules.20260827_222613' already exists. Aborting`.
fn collided_ufw_backup(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("ERROR: '")
                .and_then(|s| s.strip_suffix("' already exists. Aborting"))
        })
        .map(String::from)
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

    async fn compile(
        &self,
        rules: &[FirewallRule],
        ctx: &ApplyContext,
    ) -> Result<CompiledRules, BackendError> {
        let mut commands = Vec::new();

        // 1. Umbilical FIRST: an outbound allow to the manager so the agent's
        //    pull path survives `default deny outgoing` and any policy rule
        //    like `deny out to any`. `apply` does `ufw reset` (clears all rules)
        //    before replaying, so appending this first puts it at rule position
        //    1 — UFW first-match-wins ⇒ it's evaluated before any policy deny.
        //    Modeled on compile_ufw_rule's `from … to … port …` syntax.
        commands.push(format!(
            "ufw allow out from any to {} port {} proto tcp comment 'fw-mgr-umbilical'",
            ctx.manager_ip, ctx.manager_port
        ));

        // 2. Default policies (only when the policy set specifies one; None =
        //    system default — leave that direction untouched).
        if let Some(p) = &ctx.default_input_policy {
            commands.push(format!("ufw default {p} incoming"));
        }
        if let Some(p) = &ctx.default_output_policy {
            commands.push(format!("ufw default {p} outgoing"));
        }

        // 3. Policy rules.
        for rule in rules {
            commands.push(compile_ufw_rule(rule));
        }
        Ok(CompiledRules { commands })
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
        let (ok, _, err) = ufw_force_reset();
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
            // Shell-aware split: the compiled command embeds a single-quoted
            // comment (`comment '...'`), which `split_whitespace` would leave
            // as a literal `'foo'` arg (ufw rejects it as "Invalid syntax")
            // and would shatter a spaced comment across several args. `shlex`
            // understands the quoting and yields bare args, which go straight
            // to `Command` — no shell, so no injection even from a malicious
            // CIDR or comment.
            let parts: Vec<String> = match shlex::split(cmd) {
                Some(p) if !p.is_empty() => p,
                _ => {
                    failed += 1;
                    errors.push(format!("{}: malformed command", cmd));
                    continue;
                }
            };
            let args: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();
            let (ok, _, err) = run_cmd(&parts[0], &args);
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
        let (ok, _, err) = ufw_force_reset();
        if !ok {
            return Err(BackendError::CommandFailed(err));
        }
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        // `verbose` is required for the Default: line — plain `ufw status` never
        // prints the per-direction defaults, so the contains() checks below
        // would always report allow/deny regardless of the real policy.
        let (ok, stdout, _) = run_cmd("ufw", &["status", "verbose"]);
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
    // Direction: `out` is explicit; `in` is ufw's default so we omit it.
    if rule.direction == FirewallDirection::Out {
        cmd.push_str(" out");
    }
    if rule.log {
        cmd.push_str(" log");
    }
    // Interface binds the rule to a NIC. ufw wants `on <iface>` before the
    // protocol/from/to clauses; pick the interface matching the direction.
    let iface = if rule.direction == FirewallDirection::Out {
        rule.interface_out.as_deref()
    } else {
        rule.interface_in.as_deref()
    };
    if let Some(iface) = iface {
        cmd.push_str(&format!(" on {}", iface));
    }
    if rule.protocol != FirewallProtocol::Any {
        cmd.push_str(&format!(
            " proto {}",
            format!("{:?}", rule.protocol).to_lowercase()
        ));
    }
    // ufw requires a `from`/`to` pair — omitting them leaves a trailing
    // `port` clause dangling and ufw rejects the whole rule with "Invalid
    // syntax". Default absent CIDRs to `any`, and attach the port range to
    // the matching side (`from ... port <src>` / `to ... port <dst>`).
    let src = rule.src_cidr.as_deref().unwrap_or("any");
    let dst = rule.dst_cidr.as_deref().unwrap_or("any");
    cmd.push_str(&format!(" from {}", src));
    if let Some(range) = port_range(rule.src_port_start, rule.src_port_end) {
        cmd.push_str(&format!(" port {}", range));
    }
    cmd.push_str(&format!(" to {}", dst));
    if let Some(range) = port_range(rule.dst_port_start, rule.dst_port_end) {
        cmd.push_str(&format!(" port {}", range));
    }
    if !rule.comment.is_empty() {
        cmd.push_str(&format!(" comment '{}'", rule.comment.replace('\'', "")));
    }
    cmd
}

/// Format a port range as ufw's `port` value expects: a single port, or
/// `start:end` for a range. Returns `None` when no port is configured. The
/// `firewall_rules` CHECK constraint guarantees ports come as a (start, end)
/// pair, but the model types are `Option` so all cases are handled here.
fn port_range(start: Option<i32>, end: Option<i32>) -> Option<String> {
    match (start, end) {
        (Some(s), Some(e)) if s == e => Some(s.to_string()),
        (Some(s), Some(e)) => Some(format!("{s}:{e}")),
        (Some(s), None) => Some(s.to_string()),
        _ => None,
    }
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

    async fn compile(
        &self,
        rules: &[FirewallRule],
        ctx: &ApplyContext,
    ) -> Result<CompiledRules, BackendError> {
        // firewalld's `apply` is additive (no `ufw reset`-style clear), so it
        // has no reset-window lockout risk and the existing firewall state —
        // including whatever already allows the agent to reach the manager —
        // is preserved across every apply. The umbilical and per-policy default
        // policies are therefore UFW-only for now (the manager endpoint in
        // `ctx` is accepted but unused here); wiring firewalld zone-target
        // defaults + an outbound accept is a documented follow-up.
        let _ = ctx;
        let mut commands = Vec::new();
        for rule in rules {
            commands.push(compile_firewalld_rule(rule));
        }
        Ok(CompiledRules { commands })
    }

    async fn apply(&self, compiled: &CompiledRules) -> Result<ApplyResult, BackendError> {
        let mut applied = 0u32;
        let mut failed = 0u32;
        let mut errors = Vec::new();

        for cmd in &compiled.commands {
            // Shell-aware split (see UFW apply for rationale): respects the
            // single-quoted comment and passes bare args to `Command`.
            let parts: Vec<String> = match shlex::split(cmd) {
                Some(p) if !p.is_empty() => p,
                _ => {
                    failed += 1;
                    errors.push(format!("{}: malformed command", cmd));
                    continue;
                }
            };
            let args: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();
            let (ok, _, err) = run_cmd(&parts[0], &args);
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
        // Reset the public zone to its shipped defaults. `--remove-all` (the
        // previous implementation) was never a valid firewall-cmd option, so
        // reset always failed. `--load-zone-defaults` reports NO_DEFAULTS once
        // the zone is already at its shipped config — treat that as success so
        // reset is idempotent.
        let (ok, _, err) = run_cmd(
            "firewall-cmd",
            &["--permanent", "--load-zone-defaults=public"],
        );
        if !ok && !err.contains("NO_DEFAULTS") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn collided_ufw_backup_parses_reset_error_line() {
        let stderr = "ERROR: '/etc/ufw/before.rules.20260827_222613' already exists. Aborting\n";
        assert_eq!(
            collided_ufw_backup(stderr),
            Some("/etc/ufw/before.rules.20260827_222613".to_string())
        );
        assert_eq!(collided_ufw_backup("ERROR: something else"), None);
        assert_eq!(collided_ufw_backup(""), None);
    }

    fn allow_rule(name: &str) -> FirewallRule {
        FirewallRule {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: String::new(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::In,
            protocol: FirewallProtocol::Tcp,
            src_cidr: None,
            src_port_start: None,
            src_port_end: None,
            dst_cidr: None,
            dst_port_start: Some(22),
            dst_port_end: Some(22),
            interface_in: None,
            interface_out: None,
            comment: String::new(),
            log: false,
            priority: 0,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ctx(def_in: Option<&str>, def_out: Option<&str>, ip: &str, port: u16) -> ApplyContext {
        ApplyContext {
            manager_ip: ip.to_string(),
            manager_port: port,
            default_input_policy: def_in.map(String::from),
            default_output_policy: def_out.map(String::from),
        }
    }

    #[tokio::test]
    async fn ufw_compile_umbilical_first_then_defaults_then_rules() {
        let c = UfwBackend
            .compile(
                &[allow_rule("ssh")],
                &ctx(Some("deny"), Some("deny"), "10.0.0.1", 8443),
            )
            .await
            .unwrap();
        assert_eq!(c.commands.len(), 4);
        // 1. Umbilical (outbound allow to manager) — must precede any policy deny.
        assert_eq!(
            c.commands[0],
            "ufw allow out from any to 10.0.0.1 port 8443 proto tcp comment 'fw-mgr-umbilical'"
        );
        // 2/3. Default policies.
        assert_eq!(c.commands[1], "ufw default deny incoming");
        assert_eq!(c.commands[2], "ufw default deny outgoing");
        // 4. Policy rule.
        assert!(c.commands[3].starts_with("ufw allow"));
    }

    #[tokio::test]
    async fn ufw_compile_omits_default_commands_when_system_default() {
        let c = UfwBackend
            .compile(&[allow_rule("ssh")], &ctx(None, None, "10.0.0.1", 8443))
            .await
            .unwrap();
        // Umbilical + the policy rule only; no `ufw default` commands.
        assert_eq!(c.commands.len(), 2);
        assert!(c.commands[0].contains("fw-mgr-umbilical"));
        assert!(
            !c.commands.iter().any(|c| c.starts_with("ufw default")),
            "no ufw default commands when defaults are None"
        );
    }

    #[tokio::test]
    async fn ufw_compile_umbilical_precedes_policy_deny_out() {
        // A policy that denies all outbound must not block the umbilical: the
        // umbilical is emitted first, so UFW first-match-wins lets manager
        // traffic through before the deny matches.
        let mut deny_out = allow_rule("deny-out");
        deny_out.action = FirewallAction::Deny;
        deny_out.direction = FirewallDirection::Out;
        deny_out.name = "deny-all-out".to_string();
        let c = UfwBackend
            .compile(&[deny_out], &ctx(None, Some("deny"), "10.0.0.1", 8443))
            .await
            .unwrap();
        let umbilical_idx = c
            .commands
            .iter()
            .position(|c| c.contains("fw-mgr-umbilical"))
            .unwrap();
        let deny_idx = c
            .commands
            .iter()
            .position(|c| c.starts_with("ufw deny"))
            .unwrap();
        assert!(umbilical_idx < deny_idx);
    }
}
