//! Firewall policy sets CRUD + rule assignment + preview compilation.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::{
    FirewallAction, FirewallDirection, FirewallPolicySet, FirewallPolicySetRule, FirewallProtocol,
    FirewallRule,
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
        .route(
            "/{id}/rules",
            get(list_policy_set_rules).post(add_rule_to_set),
        )
        .route("/{id}/rules/{rule_id}", delete(remove_rule_from_set))
        .route("/{id}/preview", post(preview_compilation))
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

async fn list_policy_set_rules(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicySetRulesResponse>, fw_core::AppError> {
    let rules: Vec<FirewallRule> = sqlx::query_as(
        "SELECT r.* FROM firewall_rules r
         JOIN firewall_policy_set_rules psr ON psr.rule_id = r.id
         WHERE psr.policy_set_id = $1
         ORDER BY psr.rule_order, r.priority",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(PolicySetRulesResponse { rules }))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddRuleRequest {
    pub rule_id: Uuid,
    pub rule_order: Option<i32>,
}

async fn add_rule_to_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AddRuleRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    sqlx::query(
        "INSERT INTO firewall_policy_set_rules (policy_set_id, rule_id, rule_order) VALUES ($1, $2, $3)
         ON CONFLICT (policy_set_id, rule_id) DO UPDATE SET rule_order = $3",
    )
    .bind(id)
    .bind(req.rule_id)
    .bind(req.rule_order.unwrap_or(0))
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "rule_added", "rule_id": req.rule_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::CREATED)
}

async fn remove_rule_from_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path((id, rule_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    sqlx::query("DELETE FROM firewall_policy_set_rules WHERE policy_set_id = $1 AND rule_id = $2")
        .bind(id)
        .bind(rule_id)
        .execute(&state.db)
        .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_set_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("policy_set"),
        Some(&id.to_string()),
        serde_json::json!({ "action": "rule_removed", "rule_id": rule_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
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
    let rules: Vec<FirewallRule> = sqlx::query_as(
        "SELECT r.* FROM firewall_rules r
         JOIN firewall_policy_set_rules psr ON psr.rule_id = r.id
         WHERE psr.policy_set_id = $1
         ORDER BY psr.rule_order, r.priority",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;

    let ufw_commands: Vec<String> = rules.iter().map(|r| compile_ufw_command(r)).collect();
    let firewalld_commands: Vec<String> =
        rules.iter().map(|r| compile_firewalld_command(r)).collect();

    Ok(Json(PreviewCompilationResponse {
        ufw_commands,
        firewalld_commands,
        rule_count: rules.len(),
    }))
}

fn compile_ufw_command(rule: &FirewallRule) -> String {
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
            format!("{:?}", &rule.protocol).to_lowercase()
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

fn compile_firewalld_command(rule: &FirewallRule) -> String {
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
