//! Firewall policy sets CRUD + rule assignment + preview compilation.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::{
    FirewallAction, FirewallDirection, FirewallPolicySet, FirewallProtocol, FirewallRule,
};
use serde::Serialize;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_policy_sets).post(create_policy_set))
        .route(
            "/{id}",
            get(get_policy_set)
                .put(update_policy_set)
                .delete(delete_policy_set),
        )
        // Compiled rules for the set (read-only — rules now come via groups).
        .route("/{id}/rules", get(list_policy_set_rules))
        .route("/{id}/preview", post(preview_compilation))
        // Rule-group membership (ordered) — the set is a list of rule groups.
        .route(
            "/{id}/rule-groups",
            get(list_policy_set_groups).post(add_group_to_set),
        )
        .route("/{id}/rule-groups/reorder", put(reorder_groups))
        .route(
            "/{id}/rule-groups/{group_id}",
            delete(remove_group_from_set),
        )
}

#[derive(Debug, Serialize)]
pub struct PolicySetListResponse {
    pub policy_sets: Vec<FirewallPolicySet>,
    pub total: i64,
}

async fn list_policy_sets(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<PolicySetListResponse>, fw_core::AppError> {
    let policy_sets: Vec<FirewallPolicySet> =
        sqlx::query_as("SELECT * FROM firewall_policy_sets ORDER BY name")
            .fetch_all(&state.db)
            .await?;
    let total = policy_sets.len() as i64;
    Ok(Json(PolicySetListResponse { policy_sets, total }))
}

#[derive(Debug, serde::Deserialize)]
pub struct CreatePolicySetRequest {
    pub name: String,
    pub description: Option<String>,
}

async fn create_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreatePolicySetRequest>,
) -> Result<(StatusCode, Json<FirewallPolicySet>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let ps: FirewallPolicySet = sqlx::query_as(
        "INSERT INTO firewall_policy_sets (name, description, created_by) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(&req.name)
    .bind(req.description.unwrap_or_default())
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&ps.id.to_string()),
        serde_json::json!({ "name": ps.name }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok((StatusCode::CREATED, Json(ps)))
}

async fn get_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FirewallPolicySet>, fw_core::AppError> {
    let ps: FirewallPolicySet = sqlx::query_as("SELECT * FROM firewall_policy_sets WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Policy set not found".to_string()))?;
    Ok(Json(ps))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdatePolicySetRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

async fn update_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePolicySetRequest>,
) -> Result<Json<FirewallPolicySet>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let ps: FirewallPolicySet = sqlx::query_as(
        "UPDATE firewall_policy_sets SET name = COALESCE($2, name), description = COALESCE($3, description), updated_at = NOW() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| fw_core::AppError::NotFound("Policy set not found".to_string()))?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&ps.id.to_string()),
        serde_json::json!({ "name": ps.name }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(Json(ps))
}

async fn delete_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let result = sqlx::query("DELETE FROM firewall_policy_sets WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(fw_core::AppError::NotFound(
            "Policy set not found".to_string(),
        ));
    }

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "deleted" }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct PolicySetRulesResponse {
    pub rules: Vec<FirewallRule>,
}

/// `GET /{id}/rules` — the compiled, flattened rule list for the set (rules
/// gathered from the set's rule groups in apply order). Read-only; manage
/// membership via the `/rule-groups` endpoints.
async fn list_policy_set_rules(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicySetRulesResponse>, fw_core::AppError> {
    let rules = fw_core::policy::rules_for_policy_set(&state.db, id).await?;
    Ok(Json(PolicySetRulesResponse { rules }))
}

// ── Rule-group membership ───────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PolicySetRuleGroup {
    pub rule_group_id: Uuid,
    pub name: String,
    pub description: String,
    pub set_group_order: i32,
    pub rule_count: i64,
}

#[derive(Debug, Serialize)]
pub struct PolicySetRuleGroupsResponse {
    pub rule_groups: Vec<PolicySetRuleGroup>,
}

/// `GET /{id}/rule-groups` — the rule groups included in the set, in apply order.
async fn list_policy_set_groups(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicySetRuleGroupsResponse>, fw_core::AppError> {
    let groups: Vec<PolicySetRuleGroup> = sqlx::query_as(
        "SELECT psg.rule_group_id, g.name, g.description, psg.set_group_order,
                (SELECT count(*) FROM firewall_rules r WHERE r.rule_group_id = g.id) AS rule_count
         FROM firewall_policy_set_rule_groups psg
         JOIN firewall_rule_groups g ON g.id = psg.rule_group_id
         WHERE psg.policy_set_id = $1
         ORDER BY psg.set_group_order",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(PolicySetRuleGroupsResponse {
        rule_groups: groups,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddGroupRequest {
    pub rule_group_id: Uuid,
    pub set_group_order: Option<i32>,
}

/// `POST /{id}/rule-groups` — include a rule group in the set (appended to the
/// end if no order is given).
async fn add_group_to_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AddGroupRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    sqlx::query(
        "INSERT INTO firewall_policy_set_rule_groups (policy_set_id, rule_group_id, set_group_order)
         VALUES ($1, $2, COALESCE($3, (SELECT COALESCE(MAX(set_group_order), -1) + 1 FROM firewall_policy_set_rule_groups WHERE policy_set_id = $1)))
         ON CONFLICT (policy_set_id, rule_group_id) DO UPDATE SET set_group_order = EXCLUDED.set_group_order",
    )
    .bind(id)
    .bind(req.rule_group_id)
    .bind(req.set_group_order)
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "rule_group_added", "rule_group_id": req.rule_group_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::CREATED)
}

/// `DELETE /{id}/rule-groups/{group_id}` — remove a rule group from the set.
async fn remove_group_from_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path((id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    sqlx::query(
        "DELETE FROM firewall_policy_set_rule_groups WHERE policy_set_id = $1 AND rule_group_id = $2",
    )
    .bind(id)
    .bind(group_id)
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "rule_group_removed", "rule_group_id": group_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, serde::Deserialize)]
pub struct ReorderGroupsRequest {
    /// The set's rule-group IDs in their new desired order.
    pub rule_group_ids: Vec<Uuid>,
}

/// `PUT /{id}/rule-groups/reorder` — rewrite `set_group_order` for every group
/// in the set to match the supplied order, in a single transaction.
async fn reorder_groups(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<ReorderGroupsRequest>,
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
    for (order, group_id) in req.rule_group_ids.iter().enumerate() {
        sqlx::query(
            "UPDATE firewall_policy_set_rule_groups SET set_group_order = $3
             WHERE policy_set_id = $1 AND rule_group_id = $2",
        )
        .bind(id)
        .bind(group_id)
        .bind(order as i32)
        .execute(&mut *tx)
        .await
        .map_err(fw_core::AppError::Database)?;
    }
    tx.commit().await.map_err(fw_core::AppError::Database)?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "rule_groups_reordered", "count": req.rule_group_ids.len() }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::OK)
}

#[derive(Debug, Serialize)]
pub struct PreviewCompilationResponse {
    pub ufw_commands: Vec<String>,
    pub firewalld_commands: Vec<String>,
    pub rule_count: usize,
}

async fn preview_compilation(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<PreviewCompilationResponse>, fw_core::AppError> {
    let rules = fw_core::policy::rules_for_policy_set(&state.db, id).await?;

    let ufw_commands: Vec<String> = rules.iter().map(compile_ufw_command).collect();
    let firewalld_commands: Vec<String> = rules.iter().map(compile_firewalld_command).collect();

    Ok(Json(PreviewCompilationResponse {
        ufw_commands,
        firewalld_commands,
        rule_count: rules.len(),
    }))
}

pub(crate) fn compile_ufw_command(rule: &FirewallRule) -> String {
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
    if !rule.comment.is_empty() {
        cmd.push_str(&format!(" comment '{}'", rule.comment));
    }
    cmd
}

pub(crate) fn compile_firewalld_command(rule: &FirewallRule) -> String {
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
    let src = rule.src_cidr.as_deref().unwrap_or("any");
    let port = rule
        .dst_port_start
        .map(|p| p.to_string())
        .unwrap_or_default();
    format!(
        "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"{}\" {} port port=\"{}\" protocol=\"{}\" {}'",
        src, if port.is_empty() { "" } else { "service" }, port, proto, action
    )
}
