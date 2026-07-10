//! Pull loop — the main periodic check-in cycle for the agent.
//!
//! Runs as a background tokio task. On each cycle:
//! 1. Compute current rules hash from the backend
//! 2. Call the manager's check-in endpoint
//! 3. If rules changed, apply the new rules via incremental diff
//! 4. Execute any pending actions
//! 5. Apply config updates
//! 6. Report results back to the manager
//! 7. Sleep for the configured interval, then repeat

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::backend::FirewallBackend;
use crate::config::AgentConfig;
use crate::pull_client::{CheckInRequest, CheckInResultRequest, PullClient, RuleDto};
use sha2::{Digest, Sha256};

/// Run the pull loop as a background task.
pub async fn run_pull_loop(
    backend: Arc<dyn FirewallBackend>,
    config: Arc<RwLock<AgentConfig>>,
    pull_client: PullClient,
) {
    let host_id = config.read().await.agent_id.unwrap_or_default();
    let mut interval_secs = config.read().await.pull.check_in_interval_secs;
    let mut config_version = config.read().await.pull.config_version;

    loop {
        tracing::info!(host_id = %host_id, interval = interval_secs, "Pull cycle starting");

        if let Err(e) = run_pull_cycle(&backend, &config, &pull_client, host_id, &mut interval_secs, &mut config_version).await {
            tracing::error!(error = %e, "Pull cycle failed");
        }

        tokio::time::sleep(Duration::from_secs(interval_secs.max(60) as u64)).await;
    }
}

async fn run_pull_cycle(
    backend: &Arc<dyn FirewallBackend>,
    config: &Arc<RwLock<AgentConfig>>,
    pull_client: &PullClient,
    host_id: uuid::Uuid,
    interval_secs: &mut u32,
    config_version: &mut i32,
) -> Result<()> {
    // 1. Compute current rules hash
    let current_rules = backend
        .get_current_rules()
        .await
        .context("Failed to get current rules from backend")?;
    let rules_hash = compute_rules_hash(&current_rules);

    // 2. Gather agent info
    let backend_info = backend
        .get_backend_info()
        .await
        .context("Failed to get backend info")?;
    let os_info = gather_os_info();
    let uptime = get_uptime_seconds();

    // 3. Call check-in
    let req = CheckInRequest {
        host_id,
        rules_hash: rules_hash.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_type: backend_info.backend_type.clone(),
        os_info,
        uptime_seconds: uptime,
        config_version: *config_version,
    };

    let response = pull_client.check_in(&req).await?;

    // 4. Apply config updates if present
    if let Some(ref cfg_update) = response.config {
        *interval_secs = cfg_update.check_in_interval_secs as u32;
        *config_version = cfg_update.config_version;

        {
            let mut cfg = config.write().await;
            cfg.pull.check_in_interval_secs = *interval_secs;
            cfg.pull.config_version = *config_version;
            cfg.pull.push_enabled = cfg_update.push_enabled;
            cfg.safe_mode.enabled = cfg_update.safe_mode_enabled;
            if let Some(ref backend_override) = cfg_update.backend_override {
                cfg.backend = backend_override.clone();
            }
        }
        tracing::info!(interval = *interval_secs, version = *config_version, "Config updated from manager");
    }

    // 5. Apply new rules if changed
    if response.rules_changed && !response.rules.is_empty() {
        tracing::info!(rule_count = response.rules.len(), "Rules changed, applying new ruleset");
        match apply_rules_incremental(backend, &response.rules).await {
            Ok(()) => {
                let new_hash = compute_rules_hash_dto(&response.rules);
                let result_req = CheckInResultRequest {
                    host_id,
                    action_id: None,
                    success: true,
                    error_message: None,
                    new_rules_hash: new_hash,
                };
                if let Err(e) = pull_client.report_result(&result_req).await {
                    tracing::warn!(error = %e, "Failed to report success to manager");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to apply rules");
                let result_req = CheckInResultRequest {
                    host_id,
                    action_id: None,
                    success: false,
                    error_message: Some(e.to_string()),
                    new_rules_hash: rules_hash,
                };
                if let Err(e) = pull_client.report_result(&result_req).await {
                    tracing::warn!(error = %e, "Failed to report error to manager");
                }
            }
        }
    }

    // 6. Execute pending actions
    for action in &response.pending_actions {
        tracing::info!(
            action_id = %action.id,
            action_type = %action.action_type,
            "Executing pending action"
        );
        let (success, error_msg) = execute_pending_action(backend, config, action).await;

        let result_req = CheckInResultRequest {
            host_id,
            action_id: Some(action.id),
            success,
            error_message: error_msg,
            new_rules_hash: rules_hash.clone(),
        };
        if let Err(e) = pull_client.report_result(&result_req).await {
            tracing::warn!(error = %e, "Failed to report action result to manager");
        }
    }

    Ok(())
}

/// Apply rules using incremental diff — add new rules, remove old ones.
async fn apply_rules_incremental(
    backend: &Arc<dyn FirewallBackend>,
    new_rules: &[RuleDto],
) -> Result<()> {
    let current = backend
        .get_current_rules()
        .await
        .context("Failed to get current rules")?;

    // Convert DTOs to backend rules
    let target: Vec<crate::backend::FirewallRule> = new_rules
        .iter()
        .map(|r| crate::backend::FirewallRule {
            id: Some(r.id.to_string()),
            action: match r.action.as_str() {
                "allow" => crate::backend::RuleAction::Allow,
                "deny" => crate::backend::RuleAction::Deny,
                "reject" => crate::backend::RuleAction::Reject,
                "limit" => crate::backend::RuleAction::Limit,
                "masquerade" => crate::backend::RuleAction::Masquerade,
                _ => crate::backend::RuleAction::Allow,
            },
            direction: match r.direction.as_str() {
                "in" => crate::backend::RuleDirection::Inbound,
                "out" => crate::backend::RuleDirection::Outbound,
                "forward" => crate::backend::RuleDirection::Forward,
                _ => crate::backend::RuleDirection::Inbound,
            },
            protocol: match r.protocol.as_str() {
                "tcp" => crate::backend::RuleProtocol::Tcp,
                "udp" => crate::backend::RuleProtocol::Udp,
                "icmp" => crate::backend::RuleProtocol::Icmp,
                "icmpv6" => crate::backend::RuleProtocol::Icmpv6,
                "gre" => crate::backend::RuleProtocol::Gre,
                "esp" => crate::backend::RuleProtocol::Esp,
                "ah" => crate::backend::RuleProtocol::Ah,
                "sctp" => crate::backend::RuleProtocol::Sctp,
                _ => crate::backend::RuleProtocol::Any,
            },
            source: r.src_cidr.as_deref().and_then(|s| s.parse().ok()),
            destination: r.dst_cidr.as_deref().and_then(|s| s.parse().ok()),
            source_port: r.src_port_start.map(|p| p as u16),
            destination_port: r.dst_port_start.map(|p| p as u16),
            interface: r.interface_in.clone(),
            comment: Some(r.name.clone()),
            priority: r.priority,
        })
        .collect();

    // Simple incremental: if the rule sets differ, just apply the full target set.
    // A more sophisticated diff would add/remove individual rules, but for safety
    // we do a full replace when the sets differ.
    if current.len() != target.len() || !rules_equal(&current, &target) {
        backend
            .apply_rules(&target)
            .await
            .context("Failed to apply rules to backend")?;
    }

    Ok(())
}

fn rules_equal(a: &[crate::backend::FirewallRule], b: &[crate::backend::FirewallRule]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().all(|ra| b.iter().any(|rb| rules_match(ra, rb)))
}

fn rules_match(a: &crate::backend::FirewallRule, b: &crate::backend::FirewallRule) -> bool {
    a.action == b.action
        && a.direction == b.direction
        && a.protocol == b.protocol
        && a.source == b.source
        && a.destination == b.destination
        && a.source_port == b.source_port
        && a.destination_port == b.destination_port
}

/// Execute a pending action received from the manager.
async fn execute_pending_action(
    backend: &Arc<dyn FirewallBackend>,
    _config: &Arc<RwLock<AgentConfig>>,
    action: &crate::pull_client::PendingActionDto,
) -> (bool, Option<String>) {
    match action.action_type.as_str() {
        "apply_rules" => {
            // The rules should be in the payload — fetch policy and apply
            match pull_client_fetch_and_apply(backend, action).await {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            }
        }
        "rollback" => {
            // Rollback to previous ruleset — clear and let next check-in re-apply
            match backend.clear_rules().await {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            }
        }
        "safe_mode_on" => {
            // TODO: trigger safe mode
            tracing::warn!("safe_mode_on action not yet implemented");
            (true, None)
        }
        "safe_mode_off" => {
            // TODO: disable safe mode
            tracing::warn!("safe_mode_off action not yet implemented");
            (true, None)
        }
        "reload_config" => {
            // Config was already updated in the check-in response
            (true, None)
        }
        "agent_upgrade" => {
            // TODO: trigger self-update
            tracing::warn!("agent_upgrade action not yet implemented");
            (true, None)
        }
        _ => (
            false,
            Some(format!("Unknown action type: {}", action.action_type)),
        ),
    }
}

async fn pull_client_fetch_and_apply(
    _backend: &Arc<dyn FirewallBackend>,
    _action: &crate::pull_client::PendingActionDto,
) -> Result<()> {
    // In a real implementation, this would extract rules from the payload
    // or fetch them from the manager. For now, this is a stub.
    tracing::info!("apply_rules pending action — rules will be applied on next check-in");
    Ok(())
}

fn compute_rules_hash(rules: &[crate::backend::FirewallRule]) -> String {
    let mut hasher = Sha256::new();
    for rule in rules {
        if let Some(ref id) = rule.id {
            hasher.update(id.as_bytes());
        }
        hasher.update(format!("{:?}", rule.action).as_bytes());
        hasher.update(format!("{:?}", rule.direction).as_bytes());
        hasher.update(format!("{:?}", rule.protocol).as_bytes());
        if let Some(ref src) = rule.source {
            hasher.update(src.to_string().as_bytes());
        }
        if let Some(ref dst) = rule.destination {
            hasher.update(dst.to_string().as_bytes());
        }
        if let Some(port) = rule.destination_port {
            hasher.update(port.to_le_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn compute_rules_hash_dto(rules: &[RuleDto]) -> String {
    let mut hasher = Sha256::new();
    for rule in rules {
        hasher.update(rule.id.as_bytes());
        hasher.update(rule.action.as_bytes());
        hasher.update(rule.direction.as_bytes());
        hasher.update(rule.protocol.as_bytes());
        if let Some(ref cidr) = rule.src_cidr {
            hasher.update(cidr.as_bytes());
        }
        if let Some(ref cidr) = rule.dst_cidr {
            hasher.update(cidr.as_bytes());
        }
        if let Some(port) = rule.dst_port_start {
            hasher.update(port.to_le_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn gather_os_info() -> serde_json::Value {
    serde_json::json!({
        "hostname": hostname(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_uptime_seconds() -> i64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as i64)
        .unwrap_or(0)
}