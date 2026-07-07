use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::server::AgentState;

#[derive(Debug, Deserialize)]
pub struct ApplyRequest {
    pub rules: Vec<DeployedRule>,
    pub job_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeployedRule {
    pub name: String,
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_cidr: Option<String>,
    pub src_port_start: Option<i32>,
    pub src_port_end: Option<i32>,
    pub dst_cidr: Option<String>,
    pub dst_port_start: Option<i32>,
    pub dst_port_end: Option<i32>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    pub log: bool,
    pub priority: i32,
}

#[derive(Debug, Serialize)]
pub struct ApplyResponse {
    pub job_id: String,
    pub applied: u32,
    pub failed: u32,
    pub snapshot_hash: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotResponse {
    pub rules: Vec<String>,
    pub snapshot_hash: String,
    pub rule_count: usize,
}

pub async fn snapshot_handler(State(state): State<Arc<AgentState>>) -> Json<SnapshotResponse> {
    if let Some(backend) = &state.backend {
        match backend.snapshot().await {
            Ok(snap) => {
                return Json(SnapshotResponse {
                    rules: snap.rules,
                    snapshot_hash: snap.hash,
                    rule_count: 0, // Will be set from snap.rules.len()
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to capture snapshot");
            }
        }
    }
    Json(SnapshotResponse {
        rules: vec![],
        snapshot_hash: String::new(),
        rule_count: 0,
    })
}

pub async fn apply_handler(
    State(state): State<Arc<AgentState>>,
    Json(req): Json<ApplyRequest>,
) -> Json<ApplyResponse> {
    // Check safe mode
    if state.safe_mode.is_active() {
        return Json(ApplyResponse {
            job_id: req.job_id,
            applied: 0,
            failed: 0,
            snapshot_hash: String::new(),
            error: Some("Agent in safe mode — manager unreachable".to_string()),
        });
    }

    // Check protected CIDRs (SEC-006)
    if !state.config.protected_cidrs.is_empty() {
        let rule_names: Vec<String> = req.rules.iter().map(|r| r.name.clone()).collect();
        // Convert DeployedRule to FirewallRule for protected CIDR check
        let fw_rules: Vec<fw_core::models::FirewallRule> = req
            .rules
            .iter()
            .map(|r| fw_core::models::FirewallRule {
                id: uuid::Uuid::nil(),
                name: r.name.clone(),
                description: String::new(),
                action: parse_action(&r.action),
                direction: parse_direction(&r.direction),
                protocol: parse_protocol(&r.protocol),
                src_cidr: r.src_cidr.clone(),
                src_port_start: r.src_port_start,
                src_port_end: r.src_port_end,
                dst_cidr: r.dst_cidr.clone(),
                dst_port_start: r.dst_port_start,
                dst_port_end: r.dst_port_end,
                interface_in: r.interface_in.clone(),
                interface_out: r.interface_out.clone(),
                comment: r.comment.clone().unwrap_or_default(),
                log: r.log,
                priority: r.priority,
                created_by: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .collect();

        if let Err(violations) = crate::protected_cidrs::check_rules_against_protected(
            &fw_rules,
            &state.config.protected_cidrs,
        ) {
            return Json(ApplyResponse {
                job_id: req.job_id,
                applied: 0,
                failed: 0,
                snapshot_hash: String::new(),
                error: Some(format!(
                    "Protected CIDR violation: {}",
                    violations.join("; ")
                )),
            });
        }
        tracing::debug!(rules = ?rule_names, "Protected CIDR check passed");
    }

    // Apply via backend
    if let Some(backend) = &state.backend {
        let fw_rules: Vec<fw_core::models::FirewallRule> = req
            .rules
            .iter()
            .map(|r| fw_core::models::FirewallRule {
                id: uuid::Uuid::nil(),
                name: r.name.clone(),
                description: String::new(),
                action: parse_action(&r.action),
                direction: parse_direction(&r.direction),
                protocol: parse_protocol(&r.protocol),
                src_cidr: r.src_cidr.clone(),
                src_port_start: r.src_port_start,
                src_port_end: r.src_port_end,
                dst_cidr: r.dst_cidr.clone(),
                dst_port_start: r.dst_port_start,
                dst_port_end: r.dst_port_end,
                interface_in: r.interface_in.clone(),
                interface_out: r.interface_out.clone(),
                comment: r.comment.clone().unwrap_or_default(),
                log: r.log,
                priority: r.priority,
                created_by: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .collect();

        match backend.compile(&fw_rules).await {
            Ok(compiled) => {
                match backend.apply(&compiled).await {
                    Ok(result) => {
                        // Record manager contact for safe mode
                        state.safe_mode.record_manager_contact();
                        return Json(ApplyResponse {
                            job_id: req.job_id,
                            applied: result.applied,
                            failed: result.failed,
                            snapshot_hash: result.snapshot_hash,
                            error: result.error,
                        });
                    }
                    Err(e) => {
                        return Json(ApplyResponse {
                            job_id: req.job_id,
                            applied: 0,
                            failed: 0,
                            snapshot_hash: String::new(),
                            error: Some(format!("Apply failed: {}", e)),
                        });
                    }
                }
            }
            Err(e) => {
                return Json(ApplyResponse {
                    job_id: req.job_id,
                    applied: 0,
                    failed: 0,
                    snapshot_hash: String::new(),
                    error: Some(format!("Compile failed: {}", e)),
                });
            }
        }
    }

    Json(ApplyResponse {
        job_id: req.job_id,
        applied: 0,
        failed: 0,
        snapshot_hash: String::new(),
        error: Some("No firewall backend detected".to_string()),
    })
}

pub async fn reset_handler(State(state): State<Arc<AgentState>>) -> Json<serde_json::Value> {
    if let Some(backend) = &state.backend {
        match backend.reset().await {
            Ok(_) => {
                return Json(serde_json::json!({"status": "ok", "backend": state.backend_name}));
            }
            Err(e) => {
                return Json(serde_json::json!({"status": "error", "message": e.to_string()}));
            }
        }
    }
    Json(serde_json::json!({"status": "error", "message": "No backend detected"}))
}

fn parse_action(s: &str) -> fw_core::models::FirewallAction {
    match s.to_lowercase().as_str() {
        "allow" => fw_core::models::FirewallAction::Allow,
        "deny" => fw_core::models::FirewallAction::Deny,
        "reject" => fw_core::models::FirewallAction::Reject,
        "limit" => fw_core::models::FirewallAction::Limit,
        "masquerade" => fw_core::models::FirewallAction::Masquerade,
        _ => fw_core::models::FirewallAction::Allow,
    }
}

fn parse_direction(s: &str) -> fw_core::models::FirewallDirection {
    match s.to_lowercase().as_str() {
        "in" => fw_core::models::FirewallDirection::In,
        "out" => fw_core::models::FirewallDirection::Out,
        "forward" => fw_core::models::FirewallDirection::Forward,
        _ => fw_core::models::FirewallDirection::In,
    }
}

fn parse_protocol(s: &str) -> fw_core::models::FirewallProtocol {
    match s.to_lowercase().as_str() {
        "any" => fw_core::models::FirewallProtocol::Any,
        "tcp" => fw_core::models::FirewallProtocol::Tcp,
        "udp" => fw_core::models::FirewallProtocol::Udp,
        "icmp" => fw_core::models::FirewallProtocol::Icmp,
        "icmpv6" => fw_core::models::FirewallProtocol::Icmpv6,
        "gre" => fw_core::models::FirewallProtocol::Gre,
        "esp" => fw_core::models::FirewallProtocol::Esp,
        "ah" => fw_core::models::FirewallProtocol::Ah,
        "sctp" => fw_core::models::FirewallProtocol::Sctp,
        _ => fw_core::models::FirewallProtocol::Any,
    }
}
