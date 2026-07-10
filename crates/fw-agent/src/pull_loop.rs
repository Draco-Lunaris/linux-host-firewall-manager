//! Pull loop — the main periodic check-in cycle for the agent.
//!
//! Runs as a background tokio task. On each cycle:
//! 1. Compute current rules hash from the backend snapshot
//! 2. Call the manager's check-in endpoint
//! 3. If rules changed, compile and apply the new rules
//! 4. Execute any pending actions
//! 5. Apply config updates
//! 6. Report results back to the manager
//! 7. Sleep for the configured interval, then repeat

use anyhow::{Context, Result};
use fw_core::models::{
    FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::backend::{FirewallBackend, BackendError};
use crate::config::AgentConfig;
use crate::pull_client::{CheckInRequest, CheckInResultRequest, PullClient, RuleDto};

/// Run the pull loop as a background task.
pub async fn run_pull_loop(
    backend: Arc<dyn FirewallBackend>,
    config: Arc<RwLock<AgentConfig>>,
    pull_client: PullClient,
) {
    let host_id = config
        .read()
        .await
        .host_id
        .as_ref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or_default();
    let mut interval_secs = config.read().await.pull.check_in_interval_secs;
    let mut config_version = config.read().await.pull.config_version;

    loop {
        tracing::info!(host_id = %host_id, interval = interval_secs, "Pull cycle starting");

        if let Err(e) =
            run_pull_cycle(&backend, &config, &pull_client, host_id, &mut interval_secs, &mut config_version)
                .await
        {
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
    // 1. Compute current rules hash from backend snapshot
    let snapshot = backend.snapshot().await.context("Failed to get backend snapshot")?;
    let rules_hash = snapshot.hash;

    // 2. Gather agent info
    let backend_status = backend.status().await.context("Failed to get backend status")?;
    let os_info = gather_os_info();
    let uptime = get_uptime_seconds();

    // 3. Call check-in
    let req = CheckInRequest {
        host_id,
        rules_hash: rules_hash.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_type: backend.name().to_string(),
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
            cfg.safe_mode_enabled = cfg_update.safe_mode_enabled;
        }
        tracing::info!(interval = *interval_secs, version = *config_version, "Config updated from manager");
    }

    // 5. Apply new rules if changed
    if response.rules_changed && !response.rules.is_empty() {
        tracing::info!(rule_count = response.rules.len(), "Rules changed, applying new ruleset");
        match apply_rules_from_dto(backend, &response.rules).await {
            Ok(new_hash) => {
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
        let (success, error_msg) = execute_pending_action(backend, action).await;

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

/// Convert RuleDto list to FirewallRule list, compile, and apply via backend.
async fn apply_rules_from_dto(
    backend: &Arc<dyn FirewallBackend>,
    dtos: &[RuleDto],
) -> Result<String> {
    let rules: Vec<FirewallRule> = dtos.iter().map(dto_to_rule).collect();

    // Compile the rules
    let compiled = backend
        .compile(&rules)
        .await
        .map_err(|e| anyhow::anyhow!("Compile failed: {}", e))?;

    // Apply the compiled rules
    let result = backend
        .apply(&compiled)
        .await
        .map_err(|e| anyhow::anyhow!("Apply failed: {}", e))?;

    if result.failed > 0 {
        anyhow::bail!("{} rules failed to apply", result.failed);
    }

    Ok(result.snapshot_hash)
}

/// Convert a RuleDto (from manager API) to a FirewallRule (domain model).
fn dto_to_rule(dto: &RuleDto) -> FirewallRule {
    FirewallRule {
        id: dto.id,
        name: dto.name.clone(),
        description: String::new(),
        action: match dto.action.as_str() {
            "allow" => FirewallAction::Allow,
            "deny" => FirewallAction::Deny,
            "reject" => FirewallAction::Reject,
            "limit" => FirewallAction::Limit,
            "masquerade" => FirewallAction::Masquerade,
            _ => FirewallAction::Allow,
        },
        direction: match dto.direction.as_str() {
            "in" => FirewallDirection::In,
            "out" => FirewallDirection::Out,
            "forward" => FirewallDirection::Forward,
            _ => FirewallDirection::In,
        },
        protocol: match dto.protocol.as_str() {
            "any" => FirewallProtocol::Any,
            "tcp" => FirewallProtocol::Tcp,
            "udp" => FirewallProtocol::Udp,
            "icmp" => FirewallProtocol::Icmp,
            "icmpv6" => FirewallProtocol::Icmpv6,
            "gre" => FirewallProtocol::Gre,
            "esp" => FirewallProtocol::Esp,
            "ah" => FirewallProtocol::Ah,
            "sctp" => FirewallProtocol::Sctp,
            _ => FirewallProtocol::Any,
        },
        src_cidr: dto.src_cidr.clone(),
        src_port_start: dto.src_port_start,
        src_port_end: dto.src_port_end,
        dst_cidr: dto.dst_cidr.clone(),
        dst_port_start: dto.dst_port_start,
        dst_port_end: dto.dst_port_end,
        interface_in: dto.interface_in.clone(),
        interface_out: dto.interface_out.clone(),
        comment: dto.name.clone(),
        log: dto.log,
        priority: dto.priority,
        created_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Execute a pending action received from the manager.
async fn execute_pending_action(
    backend: &Arc<dyn FirewallBackend>,
    action: &crate::pull_client::PendingActionDto,
) -> (bool, Option<String>) {
    match action.action_type.as_str() {
        "rollback" => match backend.reset().await {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        },
        "safe_mode_on" => {
            tracing::warn!("safe_mode_on action not yet implemented");
            (true, None)
        }
        "safe_mode_off" => {
            tracing::warn!("safe_mode_off action not yet implemented");
            (true, None)
        }
        "reload_config" => (true, None),
        "agent_upgrade" => {
            tracing::warn!("agent_upgrade action not yet implemented");
            (true, None)
        }
        "apply_rules" => {
            // Rules will be applied on next check-in cycle if hash differs
            tracing::info!("apply_rules action — will be applied on next check-in");
            (true, None)
        }
        _ => (false, Some(format!("Unknown action type: {}", action.action_type))),
    }
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