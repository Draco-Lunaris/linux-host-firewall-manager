//! Firewall rules CRUD + rule policy engine (SEC-003).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::{
    FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule, FIREWALL_RULE_COLS,
};
use fw_core::policy::{check_against_protected_cidrs, check_rule};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        // Rule creation is group-scoped: POST /api/v1/rule-groups/{id}/rules.
        // This endpoint lists/inspects/edits existing rules across all groups.
        .route("/", get(list_rules))
        .route("/flagged", get(list_flagged_rules))
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
    let rules: Vec<FirewallRule> = sqlx::query_as(&format!(
        "SELECT {FIREWALL_RULE_COLS} FROM firewall_rules ORDER BY priority, name"
    ))
    .fetch_all(&state.db)
    .await?;
    let total = rules.len() as i64;
    Ok(Json(RuleListResponse { rules, total }))
}

/// `GET /rules/flagged` — rules that require admin approval (broad allows),
/// for the RulesPage "Flagged" filter (SEC-003).
async fn list_flagged_rules(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<FirewallRule>>, fw_core::AppError> {
    let rules: Vec<FirewallRule> = sqlx::query_as(&format!(
        "SELECT {FIREWALL_RULE_COLS} FROM firewall_rules ORDER BY priority, name"
    ))
    .fetch_all(&state.db)
    .await?;
    let flagged: Vec<FirewallRule> = rules
        .into_iter()
        .filter(|r| fw_core::policy::check_rule(r).requires_approval)
        .collect();
    Ok(Json(flagged))
}

async fn get_rule(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FirewallRule>, fw_core::AppError> {
    let rule: FirewallRule = sqlx::query_as(&format!(
        "SELECT {FIREWALL_RULE_COLS} FROM firewall_rules WHERE id = $1"
    ))
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

    let rule: FirewallRule = sqlx::query_as(&format!(
        "UPDATE firewall_rules SET
            name = COALESCE($2, name),
            description = COALESCE($3, description),
            action = COALESCE($4, action),
            direction = COALESCE($5, direction),
            protocol = COALESCE($6, protocol),
            src_cidr = COALESCE($7::inet, src_cidr),
            src_port_start = COALESCE($8, src_port_start),
            src_port_end = COALESCE($9, src_port_end),
            dst_cidr = COALESCE($10::inet, dst_cidr),
            dst_port_start = COALESCE($11, dst_port_start),
            dst_port_end = COALESCE($12, dst_port_end),
            interface_in = COALESCE($13, interface_in),
            interface_out = COALESCE($14, interface_out),
            comment = COALESCE($15, comment),
            log = COALESCE($16, log),
            priority = COALESCE($17, priority),
            updated_at = NOW()
         WHERE id = $1 RETURNING {FIREWALL_RULE_COLS}"
    ))
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
    let rule: FirewallRule = sqlx::query_as(&format!(
        "SELECT {FIREWALL_RULE_COLS} FROM firewall_rules WHERE id = $1"
    ))
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
