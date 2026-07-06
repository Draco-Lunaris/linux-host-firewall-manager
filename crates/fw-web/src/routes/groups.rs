//! Groups CRUD.

use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::Group;
use uuid::Uuid;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route("/{id}", get(get_group).delete(delete_group))
        .route(
            "/{id}/hosts/{host_id}",
            post(add_host_to_group).delete(remove_host_from_group),
        )
}

async fn list_groups(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<Group>>, fw_core::AppError> {
    let groups: Vec<Group> = sqlx::query_as("SELECT * FROM groups ORDER BY name")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(groups))
}

async fn create_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<Group>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    let group: Group =
        sqlx::query_as("INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING *")
            .bind(&req.name)
            .bind(req.description.unwrap_or_default())
            .fetch_one(&state.db)
            .await?;
    Ok((StatusCode::CREATED, Json(group)))
}

async fn get_group(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Group>, fw_core::AppError> {
    let group: Group = sqlx::query_as("SELECT * FROM groups WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Group not found".to_string()))?;
    Ok(Json(group))
}

async fn delete_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_host_to_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path((id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query(
        "INSERT INTO host_groups (host_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(host_id)
    .bind(id)
    .execute(&state.db)
    .await?;
    Ok(StatusCode::CREATED)
}

async fn remove_host_from_group(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path((id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM host_groups WHERE host_id = $1 AND group_id = $2")
        .bind(host_id)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}
