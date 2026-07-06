//! Firewall rules CRUD + rule policy engine (SEC-003).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    routing::{get, post, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
use fw_core::policy::{check_against_protected_cidrs, check_rule, PolicyCheckResult};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_rules).post(create_rule))
        .route("/{id}", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/{id}/validate", post(validate_rule))
}

#[derive(Debug, Serialize)]
pub struct RuleListResponse {
    pub rules: Vec<FirewallRule>,
    pub total: i64,
}

async fn list_rules(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<RuleListResponse>, fw_core::AppError> {
    let rules: Vec<FirewallRule> =
        sqlx::query_as("SELECT * FROM firewall_rules ORDER BY priority, name")
            .fetch_all(&state.db)
            .await?;
    let total = rules.len() as i64;
    Ok(Json(RuleListResponse { rules, total }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub action: FirewallAction,
    pub direction: FirewallDirection,
    pub protocol: FirewallProtocol,
    pub src_cidr: Option<String>,
    pub src_port_start: Option<i32>,
    pub src_port_end: Option<i32>,
    pub dst_cidr: Option<String>,
    pub dst_port_start: Option<i32>,
    pub dst_port_end: Option<i32>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    pub log: Option<bool>,
    pub priority: Option<i32>,
}

async fn create_rule(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<FirewallRule>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let rule = sqlx::query_as(
        "INSERT INTO firewall_rules (name, description, action, direction, protocol, src_cidr, src_port_start, src_port_end, dst_cidr, dst_port_start, dst_port_end, interface_in, interface_out, comment, log, priority, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         RETURNING *",
    )
    .bind(&req.name)
    .bind(req.description.unwrap_or_default())
    .bind(&req.action)
    .bind(&req.direction)
    .bind(&req.protocol)
    .bind(&req.src_cidr)
    .bind(req.src_port_start)
    .bind(req.src_port_end)
    .bind(&req.dst_cidr)
    .bind(req.dst_port_start)
    .bind(req.dst_port_end)
    .bind(&req.interface_in)
    .bind(&req.interface_out)
    .bind(req.comment.unwrap_or_default())
    .bind(req.log.unwrap_or(false))
    .bind(req.priority.unwrap_or(1000))
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    // Run policy engine check (SEC-003)
    let policy_result = check_rule(&rule);
    let decision = if policy_result.requires_approval {
        "flagged"
    } else {
        "auto_approved"
    };
    let _ = sqlx::query(
        "INSERT INTO rule_policy_decisions (rule_id, decision, reason) VALUES ($1, $2, $3)",
    )
    .bind(rule.id)
    .bind(decision)
    .bind(&policy_result.reason)
    .execute(&state.db)
    .await;

    // Audit log
    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule"),
        Some(&rule.id.to_string()),
        serde_json::json!({ "name": rule.name, "policy_decision": decision }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok((StatusCode::CREATED, Json(rule)))
}

async fn get_rule(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FirewallRule>, fw_core::AppError> {
    let rule: FirewallRule = sqlx::query_as("SELECT * FROM firewall_rules WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Rule not found".to_string()))?;
    Ok(Json(rule))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub action: Option<FirewallAction>,
    pub direction: Option<FirewallDirection>,
    pub protocol: Option<FirewallProtocol>,
    pub src_cidr: Option<String>,
    pub src_port_start: Option<i32>,
    pub src_port_end: Option<i32>,
    pub dst_cidr: Option<String>,
    pub dst_port_start: Option<i32>,
    pub dst_port_end: Option<i32>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    pub log: Option<bool>,
    pub priority: Option<i32>,
}

async fn update_rule(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<FirewallRule>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let rule: FirewallRule = sqlx::query_as(
        "UPDATE firewall_rules SET
            name = COALESCE($2, name),
            description = COALESCE($3, description),
            action = COALESCE($4, action),
            direction = COALESCE($5, direction),
            protocol = COALESCE($6, protocol),
            src_cidr = COALESCE($7, src_cidr),
            src_port_start = COALESCE($8, src_port_start),
            src_port_end = COALESCE($9, src_port_end),
            dst_cidr = COALESCE($10, dst_cidr),
            dst_port_start = COALESCE($11, dst_port_start),
            dst_port_end = COALESCE($12, dst_port_end),
            interface_in = COALESCE($13, interface_in),
            interface_out = COALESCE($14, interface_out),
            comment = COALESCE($15, comment),
            log = COALESCE($16, log),
            priority = COALESCE($17, priority),
            updated_at = NOW()
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.action)
    .bind(&req.direction)
    .bind(&req.protocol)
    .bind(&req.src_cidr)
    .bind(req.src_port_start)
    .bind(req.src_port_end)
    .bind(&req.dst_cidr)
    .bind(req.dst_port_start)
    .bind(req.dst_port_end)
    .bind(&req.interface_in)
    .bind(&req.interface_out)
    .bind(&req.comment)
    .bind(req.log)
    .bind(req.priority)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| fw_core::AppError::NotFound("Rule not found".to_string()))?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_updated",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule"),
        Some(&rule.id.to_string()),
        serde_json::json!({ "name": rule.name }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(Json(rule))
}

async fn delete_rule(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let result = sqlx::query("DELETE FROM firewall_rules WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(fw_core::AppError::NotFound("Rule not found".to_string()));
    }

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_deleted",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct ValidateRuleResponse {
    pub allowed: bool,
    pub requires_approval: bool,
    pub reason: String,
    pub protected_cidr_check: Option<String>,
}

async fn validate_rule(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ValidateRuleResponse>, fw_core::AppError> {
    let rule: FirewallRule = sqlx::query_as("SELECT * FROM firewall_rules WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Rule not found".to_string()))?;

    let policy_result = check_rule(&rule);

    // Check against all protected CIDRs across all hosts
    let protected_cidrs: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT cidr::text FROM host_protected_cidrs")
            .fetch_all(&state.db)
            .await?;

    let cidr_check = check_against_protected_cidrs(&rule, &protected_cidrs);

    Ok(Json(ValidateRuleResponse {
        allowed: policy_result.allowed && cidr_check.allowed,
        requires_approval: policy_result.requires_approval,
        reason: if !cidr_check.allowed {
            cidr_check.reason.clone()
        } else {
            policy_result.reason
        },
        protected_cidr_check: if !cidr_check.allowed {
            Some(cidr_check.reason)
        } else {
            None
        },
    }))
}
