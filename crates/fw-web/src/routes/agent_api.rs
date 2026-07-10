//! Agent-facing API endpoints for the pull model.
//!
//! These endpoints are called by agents (not operators) and authenticated
//! via mTLS client certificate, not JWT. The agent's host_id is extracted
//! from the certificate's CN field.
//!
//! Endpoints:
//! - POST /api/v1/agent/check-in — agent calls on interval to report state and fetch updates
//! - POST /api/v1/agent/check-in/result — agent reports result of applying rules or actions
//! - GET /api/v1/agent/policy — agent fetches its current assigned policy set

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/check-in", post(check_in))
        .route("/check-in/result", post(check_in_result))
        .route("/policy", get(get_policy))
}

// ── Request/Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CheckInRequest {
    pub host_id: Uuid,
    pub rules_hash: String,
    pub agent_version: String,
    pub backend_type: String,
    pub os_info: serde_json::Value,
    pub uptime_seconds: i64,
    pub config_version: i32,
}

#[derive(Debug, Serialize)]
pub struct CheckInResponse {
    pub rules_changed: bool,
    pub rules: Vec<RuleDto>,
    pub config: Option<ConfigUpdate>,
    pub pending_actions: Vec<PendingActionDto>,
    pub agent_update: Option<AgentUpdateInfo>,
}

#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: Uuid,
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
    pub priority: i32,
    pub log: bool,
}

#[derive(Debug, Serialize)]
pub struct ConfigUpdate {
    pub check_in_interval_secs: i32,
    pub push_enabled: bool,
    pub safe_mode_enabled: bool,
    pub backend_override: Option<String>,
    pub config_version: i32,
}

#[derive(Debug, Serialize)]
pub struct PendingActionDto {
    pub id: Uuid,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AgentUpdateInfo {
    pub latest_version: String,
    pub download_url: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckInResultRequest {
    pub host_id: Uuid,
    pub action_id: Option<Uuid>,
    pub success: bool,
    pub error_message: Option<String>,
    pub new_rules_hash: String,
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn check_in(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<CheckInRequest>,
) -> Result<Json<CheckInResponse>, fw_core::AppError> {
    // Record the check-in
    sqlx::query(
        "INSERT INTO agent_check_ins (host_id, rules_hash, agent_version, backend_type, os_info, uptime_seconds, config_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(req.host_id)
    .bind(&req.rules_hash)
    .bind(&req.agent_version)
    .bind(&req.backend_type)
    .bind(&req.os_info)
    .bind(req.uptime_seconds)
    .bind(req.config_version)
    .execute(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?;

    // Update host health to healthy (check-in = alive)
    sqlx::query("UPDATE hosts SET health_status = 'healthy', last_health_at = NOW(), agent_version = $2 WHERE id = $1")
        .bind(req.host_id)
        .bind(&req.agent_version)
        .execute(&state.db)
        .await
        .map_err(fw_core::AppError::Database)?;

    // Get the host's assigned policy set
    let policy_set_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT policy_set_id FROM host_policy_assignments WHERE host_id = $1",
    )
    .bind(req.host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?;

    // Compute expected rules hash from the assigned policy set
    let (rules, expected_hash) = if let Some(ps_id) = policy_set_id {
        let rules = fetch_rules_for_policy_set(&state.db, ps_id).await?;
        let hash = compute_rules_hash(&rules);
        (rules, hash)
    } else {
        (vec![], "empty".to_string())
    };

    // Determine if rules changed (agent's hash != expected hash)
    let rules_changed = req.rules_hash != expected_hash;

    // If hash differs, record a drift snapshot
    if rules_changed {
        let _ = sqlx::query(
            "INSERT INTO drift_snapshots (host_id, snapshot_hash, rule_count, source)
             VALUES ($1, $2, $3, 'check_in_mismatch')",
        )
        .bind(req.host_id)
        .bind(&req.rules_hash)
        .bind(rules.len() as i32)
        .execute(&state.db)
        .await;

        let _ = fw_core::audit::log_event(
            &state.db,
            "drift_detected",
            None,
            None,
            Some("host"),
            Some(&req.host_id.to_string()),
            serde_json::json!({
                "agent_hash": req.rules_hash,
                "expected_hash": expected_hash,
            }),
            None,
            None,
        )
        .await;
    }

    // Get config overrides for this host
    let config: Option<ConfigUpdate> = sqlx::query_as::<_, HostConfigOverrideRow>(
        "SELECT host_id, check_in_interval_secs, push_enabled, safe_mode_enabled, backend_override, config_version, updated_at
         FROM host_config_overrides WHERE host_id = $1",
    )
    .bind(req.host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?
    .map(|r| ConfigUpdate {
        check_in_interval_secs: r.check_in_interval_secs,
        push_enabled: r.push_enabled,
        safe_mode_enabled: r.safe_mode_enabled,
        backend_override: r.backend_override,
        config_version: r.config_version,
    });

    // Only include config in response if version changed
    let config = config.filter(|c| c.config_version > req.config_version);

    // Fetch pending actions for this host (queued, not expired)
    let pending_actions: Vec<PendingActionDto> = sqlx::query_as::<_, PendingActionRow>(
        "SELECT id, action_type::text, payload, reason
         FROM pending_actions
         WHERE host_id = $1 AND status = 'queued' AND expires_at > NOW()
         ORDER BY priority DESC, created_at",
    )
    .bind(req.host_id)
    .fetch_all(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?
    .into_iter()
    .map(|r| PendingActionDto {
        id: r.id,
        action_type: r.action_type,
        payload: r.payload,
        reason: r.reason,
    })
    .collect();

    // Mark pending actions as delivered
    if !pending_actions.is_empty() {
        let action_ids: Vec<Uuid> = pending_actions.iter().map(|a| a.id).collect();
        sqlx::query("UPDATE pending_actions SET status = 'delivered', delivered_at = NOW() WHERE id = ANY($1)")
            .bind(&action_ids)
            .execute(&state.db)
            .await
            .map_err(fw_core::AppError::Database)?;
    }

    // Agent update info (stub for now — will be wired to repo sync tables)
    let agent_update = None;

    Ok(Json(CheckInResponse {
        rules_changed,
        rules: rules.into_iter().map(rule_to_dto).collect(),
        config,
        pending_actions,
        agent_update,
    }))
}

async fn check_in_result(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<CheckInResultRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if let Some(action_id) = req.action_id {
        // Update the pending action status
        if req.success {
            sqlx::query("UPDATE pending_actions SET status = 'executed', executed_at = NOW() WHERE id = $1")
                .bind(action_id)
                .execute(&state.db)
                .await
                .map_err(fw_core::AppError::Database)?;
        } else {
            sqlx::query("UPDATE pending_actions SET status = 'failed', executed_at = NOW() WHERE id = $1")
                .bind(action_id)
                .execute(&state.db)
                .await
                .map_err(fw_core::AppError::Database)?;
        }

        let _ = fw_core::audit::log_event(
            &state.db,
            if req.success { "rule_deployed" } else { "firewall_job_failed" },
            None,
            None,
            Some("pending_action"),
            Some(&action_id.to_string()),
            serde_json::json!({
                "host_id": req.host_id,
                "success": req.success,
                "error": req.error_message,
            }),
            None,
            None,
        )
        .await;
    }

    // Record the new rules hash as a snapshot
    let _ = sqlx::query(
        "INSERT INTO drift_snapshots (host_id, snapshot_hash, rule_count, source)
         VALUES ($1, $2, 0, 'agent_report')",
    )
    .bind(req.host_id)
    .bind(&req.new_rules_hash)
    .execute(&state.db)
    .await;

    Ok(StatusCode::OK)
}

async fn get_policy(
    State(state): State<std::sync::Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<PolicyQuery>,
) -> Result<Json<Vec<RuleDto>>, fw_core::AppError> {
    let policy_set_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT policy_set_id FROM host_policy_assignments WHERE host_id = $1",
    )
    .bind(params.host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?;

    let rules = if let Some(ps_id) = policy_set_id {
        fetch_rules_for_policy_set(&state.db, ps_id).await?
    } else {
        vec![]
    };

    Ok(Json(rules.into_iter().map(rule_to_dto).collect()))
}

// ── Helper types and functions ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PolicyQuery {
    pub host_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct HostConfigOverrideRow {
    host_id: Uuid,
    check_in_interval_secs: i32,
    push_enabled: bool,
    safe_mode_enabled: bool,
    backend_override: Option<String>,
    config_version: i32,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct PendingActionRow {
    id: Uuid,
    action_type: String,
    payload: serde_json::Value,
    reason: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    action: String,
    direction: String,
    protocol: String,
    src_cidr: Option<String>,
    src_port_start: Option<i32>,
    src_port_end: Option<i32>,
    dst_cidr: Option<String>,
    dst_port_start: Option<i32>,
    dst_port_end: Option<i32>,
    interface_in: Option<String>,
    interface_out: Option<String>,
    priority: i32,
    log: bool,
}

async fn fetch_rules_for_policy_set(
    db: &sqlx::PgPool,
    policy_set_id: Uuid,
) -> Result<Vec<RuleRow>, fw_core::AppError> {
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.action::text, r.direction::text, r.protocol::text,
                r.src_cidr::text, r.src_port_start, r.src_port_end,
                r.dst_cidr::text, r.dst_port_start, r.dst_port_end,
                r.interface_in, r.interface_out, r.priority, r.log
         FROM firewall_policy_set_rules psr
         JOIN firewall_rules r ON r.id = psr.rule_id
         WHERE psr.policy_set_id = $1
         ORDER BY psr.rule_order, r.priority",
    )
    .bind(policy_set_id)
    .fetch_all(db)
    .await
    .map_err(fw_core::AppError::Database)?;
    Ok(rules)
}

fn compute_rules_hash(rules: &[RuleRow]) -> String {
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

fn rule_to_dto(r: RuleRow) -> RuleDto {
    RuleDto {
        id: r.id,
        name: r.name,
        action: r.action,
        direction: r.direction,
        protocol: r.protocol,
        src_cidr: r.src_cidr,
        src_port_start: r.src_port_start,
        src_port_end: r.src_port_end,
        dst_cidr: r.dst_cidr,
        dst_port_start: r.dst_port_start,
        dst_port_end: r.dst_port_end,
        interface_in: r.interface_in,
        interface_out: r.interface_out,
        priority: r.priority,
        log: r.log,
    }
}