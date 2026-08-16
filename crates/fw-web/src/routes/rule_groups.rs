//! Firewall rule groups — the reusable middle tier of the containment model.
//!
//! A rule group is a named, ordered collection of rules. Rules belong to
//! exactly one group (created within it), and a policy set collects an ordered
//! list of groups. Editing a rule in a group propagates to every policy set
//! that includes that group on the agent's next check-in.
//!
//! Endpoints (nested under `/api/v1/rule-groups`):
//! - GET    /                 — list groups (with rule_count + used_by_count)
//! - POST   /                 — create a group
//! - GET    /{id}             — get a group
//! - PUT    /{id}             — update a group (name/description)
//! - DELETE /{id}             — delete a group (409 if used by any policy set)
//! - GET    /{id}/rules       — the group's rules, in apply order
//! - POST   /{id}/rules       — create a rule within this group
//! - PUT    /{id}/rules/reorder — rewrite group_order for the group's rules

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::{
    FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule, FirewallRuleGroup,
    FIREWALL_RULE_COLS,
};
use fw_core::policy::check_rule;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_rule_groups).post(create_rule_group))
        .route(
            "/{id}",
            get(get_rule_group)
                .put(update_rule_group)
                .delete(delete_rule_group),
        )
        .route(
            "/{id}/rules",
            get(list_group_rules).post(create_rule_in_group),
        )
        .route("/{id}/rules/reorder", put(reorder_group_rules))
}

// ── List / create ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RuleGroupWithCounts {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub rule_count: i64,
    pub used_by_count: i64,
}

#[derive(Debug, Serialize)]
pub struct RuleGroupListResponse {
    pub rule_groups: Vec<RuleGroupWithCounts>,
    pub total: i64,
}

async fn list_rule_groups(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<RuleGroupListResponse>, fw_core::AppError> {
    let groups: Vec<RuleGroupWithCounts> = sqlx::query_as(
        "SELECT g.id, g.name, g.description, g.created_by, g.created_at, g.updated_at,
                (SELECT count(*) FROM firewall_rules r WHERE r.rule_group_id = g.id) AS rule_count,
                (SELECT count(*) FROM firewall_policy_set_rule_groups psg WHERE psg.rule_group_id = g.id) AS used_by_count
         FROM firewall_rule_groups g
         ORDER BY g.name",
    )
    .fetch_all(&state.db)
    .await?;
    let total = groups.len() as i64;
    Ok(Json(RuleGroupListResponse {
        rule_groups: groups,
        total,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

async fn create_rule_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateRuleGroupRequest>,
) -> Result<(StatusCode, Json<FirewallRuleGroup>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let group: FirewallRuleGroup = sqlx::query_as(
        "INSERT INTO firewall_rule_groups (name, description, created_by) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(&req.name)
    .bind(req.description.unwrap_or_default())
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_group_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule_group"),
        Some(&group.id.to_string()),
        serde_json::json!({ "name": group.name }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok((StatusCode::CREATED, Json(group)))
}

// ── Get / update / delete ────────────────────────────────────────────────────

async fn get_rule_group(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FirewallRuleGroup>, fw_core::AppError> {
    let group: FirewallRuleGroup =
        sqlx::query_as("SELECT * FROM firewall_rule_groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| fw_core::AppError::NotFound("Rule group not found".to_string()))?;
    Ok(Json(group))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

async fn update_rule_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRuleGroupRequest>,
) -> Result<Json<FirewallRuleGroup>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let group: FirewallRuleGroup = sqlx::query_as(
        "UPDATE firewall_rule_groups SET name = COALESCE($2, name), description = COALESCE($3, description), updated_at = NOW()
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| fw_core::AppError::NotFound("Rule group not found".to_string()))?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_group_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule_group"),
        Some(&group.id.to_string()),
        serde_json::json!({ "name": group.name }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(Json(group))
}

async fn delete_rule_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    // Block deletion if the group is still used by any policy set (RESTRICT FK
    // would abort the DELETE anyway, but this surfaces a clean 409 with context).
    let used_by: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM firewall_policy_set_rule_groups WHERE rule_group_id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    if used_by > 0 {
        return Err(fw_core::AppError::Conflict(format!(
            "Rule group is used by {used_by} policy set(s); remove it from those sets before deleting"
        )));
    }

    let result = sqlx::query("DELETE FROM firewall_rule_groups WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(fw_core::AppError::NotFound(
            "Rule group not found".to_string(),
        ));
    }

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_group_deleted",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule_group"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ── Rules within a group ─────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GroupRulesResponse {
    pub rules: Vec<FirewallRule>,
}

async fn list_group_rules(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupRulesResponse>, fw_core::AppError> {
    let rules: Vec<FirewallRule> = sqlx::query_as(&format!(
        "SELECT {FIREWALL_RULE_COLS} FROM firewall_rules
         WHERE rule_group_id = $1
         ORDER BY group_order, priority"
    ))
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(GroupRulesResponse { rules }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleInGroupRequest {
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
    /// Position within the group. If omitted, the rule is appended to the end.
    pub group_order: Option<i32>,
}

/// `POST /{id}/rules` — create a rule within this group. Reuses the SEC-003
/// policy-engine check + `rule_policy_decisions` insert from `rules::create_rule`.
async fn create_rule_in_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
    Json(req): Json<CreateRuleInGroupRequest>,
) -> Result<(StatusCode, Json<FirewallRule>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    // group_order: explicit if provided, else append after the current max.
    let rule = sqlx::query_as(&format!(
        "INSERT INTO firewall_rules (name, description, action, direction, protocol, src_cidr, src_port_start, src_port_end, dst_cidr, dst_port_start, dst_port_end, interface_in, interface_out, comment, log, priority, created_by, rule_group_id, group_order)
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9::inet, $10, $11, $12, $13, $14, $15, $16, $17, $18, COALESCE($19, (SELECT COALESCE(MAX(group_order), -1) + 1 FROM firewall_rules WHERE rule_group_id = $18)))
         RETURNING {FIREWALL_RULE_COLS}"
    ))
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
    .bind(group_id)
    .bind(req.group_order)
    .fetch_one(&state.db)
    .await?;

    // SEC-003 policy-engine check (broad-allow rules require admin approval).
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

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule"),
        Some(&rule.id.to_string()),
        serde_json::json!({ "name": rule.name, "rule_group_id": group_id, "policy_decision": decision }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok((StatusCode::CREATED, Json(rule)))
}

#[derive(Debug, Deserialize)]
pub struct ReorderGroupRulesRequest {
    /// The group's rule IDs in their new desired order.
    pub rule_ids: Vec<Uuid>,
}

/// `PUT /{id}/rules/reorder` — rewrite `group_order` for every rule in the
/// group to match the supplied order, in a single transaction.
async fn reorder_group_rules(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
    Json(req): Json<ReorderGroupRulesRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(fw_core::AppError::Database)?;
    for (order, rule_id) in req.rule_ids.iter().enumerate() {
        sqlx::query(
            "UPDATE firewall_rules SET group_order = $3
             WHERE rule_group_id = $1 AND id = $2",
        )
        .bind(group_id)
        .bind(rule_id)
        .bind(order as i32)
        .execute(&mut *tx)
        .await
        .map_err(fw_core::AppError::Database)?;
    }
    tx.commit().await.map_err(fw_core::AppError::Database)?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "rule_group_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("rule_group"),
        Some(&group_id.to_string()),
        serde_json::json!({ "action": "rules_reordered", "count": req.rule_ids.len() }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::OK)
}
