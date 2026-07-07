//! Hosts CRUD + per-host authz (SEC-008).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::Host;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_hosts))
        .route("/{id}", get(get_host).put(update_host).delete(delete_host))
        .route(
            "/{id}/policy-sets",
            get(get_host_policy_sets).post(assign_policy_set),
        )
        .route(
            "/{id}/policy-sets/{policy_set_id}",
            delete(unassign_policy_set),
        )
        .route(
            "/{id}/protected-cidrs",
            get(get_protected_cidrs).post(add_protected_cidr),
        )
        .route("/{id}/drift-snapshots", get(get_drift_snapshots))
}

async fn list_hosts(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<Host>>, fw_core::AppError> {
    let hosts: Vec<Host> = sqlx::query_as("SELECT * FROM hosts ORDER BY fqdn")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(hosts))
}

async fn get_host(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Host>, fw_core::AppError> {
    let host: Host = sqlx::query_as("SELECT * FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Host not found".to_string()))?;
    Ok(Json(host))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateHostRequest {
    pub display_name: Option<String>,
    pub notes: Option<String>,
}

async fn update_host(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHostRequest>,
) -> Result<Json<Host>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    let host: Host = sqlx::query_as(
        "UPDATE hosts SET display_name = COALESCE($2, display_name), notes = COALESCE($3, notes), updated_at = NOW() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(&req.display_name)
    .bind(&req.notes)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| fw_core::AppError::NotFound("Host not found".to_string()))?;
    Ok(Json(host))
}

async fn delete_host(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "host_removed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_host_policy_sets(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<fw_core::models::HostPolicyAssignment>>, fw_core::AppError> {
    let assignments: Vec<fw_core::models::HostPolicyAssignment> =
        sqlx::query_as("SELECT * FROM host_policy_assignments WHERE host_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    Ok(Json(assignments))
}

#[derive(Debug, serde::Deserialize)]
pub struct AssignPolicySetRequest {
    pub policy_set_id: Uuid,
}

async fn assign_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AssignPolicySetRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query(
        "INSERT INTO host_policy_assignments (host_id, policy_set_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT (host_id, policy_set_id) DO NOTHING",
    )
    .bind(id)
    .bind(req.policy_set_id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_assigned",
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        serde_json::json!({ "policy_set_id": req.policy_set_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::CREATED)
}

async fn unassign_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path((id, policy_set_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM host_policy_assignments WHERE host_id = $1 AND policy_set_id = $2")
        .bind(id)
        .bind(policy_set_id)
        .execute(&state.db)
        .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "policy_unassigned",
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&id.to_string()),
        serde_json::json!({ "policy_set_id": policy_set_id }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_protected_cidrs(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<fw_core::models::ProtectedCidr>>, fw_core::AppError> {
    let cidrs: Vec<fw_core::models::ProtectedCidr> =
        sqlx::query_as("SELECT * FROM host_protected_cidrs WHERE host_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    Ok(Json(cidrs))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddProtectedCidrRequest {
    pub cidr: String,
    pub label: Option<String>,
}

async fn add_protected_cidr(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AddProtectedCidrRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query(
        "INSERT INTO host_protected_cidrs (host_id, cidr, label, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (host_id, cidr) DO NOTHING",
    )
    .bind(id)
    .bind(&req.cidr)
    .bind(req.label.unwrap_or_default())
    .bind(auth.user_id)
    .execute(&state.db)
    .await?;
    Ok(StatusCode::CREATED)
}

async fn get_drift_snapshots(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<fw_core::models::DriftSnapshot>>, fw_core::AppError> {
    let snapshots: Vec<fw_core::models::DriftSnapshot> = sqlx::query_as(
        "SELECT * FROM drift_snapshots WHERE host_id = $1 ORDER BY captured_at DESC LIMIT 20",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(snapshots))
}
