//! Deployment endpoint — assign a policy set to hosts/groups (pull model).
//!
//! There is no job or push layer: assigning a policy set here is the only apply
//! path. The agent pulls its assigned policy on its next check-in and applies it.
//! Preview returns the compiled backend commands the agent would run.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use fw_auth::rbac::AuthUser;
use fw_core::models::FirewallRule;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::policy_sets::{compile_firewalld_command, compile_ufw_command};
use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/assign", post(assign_policy_set))
        .route("/unassign", post(unassign_policy_set))
        .route("/preview", post(preview_assignment))
}

/// Resolve the effective set of host ids from explicit host ids plus group ids.
async fn resolve_host_ids(
    db: &sqlx::PgPool,
    host_ids: &[Uuid],
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, fw_core::AppError> {
    let mut ids: Vec<Uuid> = host_ids.to_vec();

    if !group_ids.is_empty() {
        let group_hosts: Vec<Uuid> =
            sqlx::query_scalar("SELECT host_id FROM host_groups WHERE group_id = ANY($1)")
                .bind(group_ids)
                .fetch_all(db)
                .await?;
        ids.extend(group_hosts);
    }

    ids.sort();
    ids.dedup();
    Ok(ids)
}

#[derive(Debug, Deserialize)]
pub struct AssignRequest {
    pub policy_set_id: Uuid,
    pub host_ids: Vec<Uuid>,
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AssignResponse {
    pub policy_set_id: Uuid,
    pub assigned_count: usize,
    pub host_ids: Vec<Uuid>,
}

async fn assign_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<AssignRequest>,
) -> Result<(StatusCode, Json<AssignResponse>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let host_ids = resolve_host_ids(&state.db, &req.host_ids, &req.group_ids).await?;
    if host_ids.is_empty() {
        return Err(fw_core::AppError::BadRequest(
            "No hosts selected".to_string(),
        ));
    }

    let mut assigned = 0usize;
    for host_id in &host_ids {
        // SEC-012: operators may only assign to hosts in their groups.
        let can_access = fw_auth::can_access_host(&state.db, &auth, *host_id)
            .await
            .unwrap_or(false);
        if !can_access {
            return Err(fw_core::AppError::Forbidden(format!(
                "Operator {} cannot access host {}",
                auth.username, host_id
            )));
        }

        let result = sqlx::query(
            "INSERT INTO host_policy_assignments (host_id, policy_set_id, assigned_by)
             VALUES ($1, $2, $3)
             ON CONFLICT (host_id, policy_set_id) DO NOTHING",
        )
        .bind(host_id)
        .bind(req.policy_set_id)
        .bind(auth.user_id)
        .execute(&state.db)
        .await?;

        if result.rows_affected() > 0 {
            assigned += 1;
        }

        let _ = fw_core::audit::log_event(
            &state.db,
            "policy_assigned",
            Some(auth.user_id),
            Some(&auth.username),
            Some("host"),
            Some(&host_id.to_string()),
            serde_json::json!({ "policy_set_id": req.policy_set_id }),
            auth.ip.map(|ip| ip.to_string()).as_deref(),
            None,
        )
        .await;
    }

    Ok((
        StatusCode::OK,
        Json(AssignResponse {
            policy_set_id: req.policy_set_id,
            assigned_count: assigned,
            host_ids,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct UnassignRequest {
    pub policy_set_id: Uuid,
    pub host_ids: Vec<Uuid>,
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
}

async fn unassign_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<UnassignRequest>,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let host_ids = resolve_host_ids(&state.db, &req.host_ids, &req.group_ids).await?;

    for host_id in &host_ids {
        sqlx::query(
            "DELETE FROM host_policy_assignments WHERE host_id = $1 AND policy_set_id = $2",
        )
        .bind(host_id)
        .bind(req.policy_set_id)
        .execute(&state.db)
        .await?;

        let _ = fw_core::audit::log_event(
            &state.db,
            "policy_unassigned",
            Some(auth.user_id),
            Some(&auth.username),
            Some("host"),
            Some(&host_id.to_string()),
            serde_json::json!({ "policy_set_id": req.policy_set_id }),
            auth.ip.map(|ip| ip.to_string()).as_deref(),
            None,
        )
        .await;
    }

    Ok(Json(serde_json::json!({
        "policy_set_id": req.policy_set_id,
        "unassigned_from": host_ids.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    pub policy_set_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub ufw_command: Vec<String>,
    pub firewalld_command: Vec<String>,
    pub rule_count: usize,
}

async fn preview_assignment(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, fw_core::AppError> {
    let rules: Vec<FirewallRule> = sqlx::query_as(
        "SELECT r.* FROM firewall_rules r
         JOIN firewall_policy_set_rules psr ON psr.rule_id = r.id
         WHERE psr.policy_set_id = $1
         ORDER BY psr.rule_order, r.priority",
    )
    .bind(req.policy_set_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(PreviewResponse {
        ufw_command: rules.iter().map(compile_ufw_command).collect(),
        firewalld_command: rules.iter().map(compile_firewalld_command).collect(),
        rule_count: rules.len(),
    }))
}
