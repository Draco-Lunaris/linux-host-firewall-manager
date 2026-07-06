//! Maintenance windows CRUD.

use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::MaintenanceWindow;
use uuid::Uuid;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_windows).post(create_window))
        .route(
            "/{id}",
            get(get_window).put(update_window).delete(delete_window),
        )
}

async fn list_windows(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<MaintenanceWindow>>, fw_core::AppError> {
    let windows: Vec<MaintenanceWindow> =
        sqlx::query_as("SELECT * FROM maintenance_windows ORDER BY start_at DESC LIMIT 50")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(windows))
}

async fn create_window(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateWindowRequest>,
) -> Result<(StatusCode, Json<MaintenanceWindow>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    let mw: MaintenanceWindow = sqlx::query_as("INSERT INTO maintenance_windows (host_id, label, recurrence, start_at, duration_minutes) VALUES ($1, $2, $3, $4, $5) RETURNING *").bind(req.host_id).bind(&req.label).bind(&req.recurrence).bind(req.start_at).bind(req.duration_minutes.unwrap_or(60)).fetch_one(&state.db).await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "maintenance_window_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&mw.id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok((StatusCode::CREATED, Json(mw)))
}

async fn get_window(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MaintenanceWindow>, fw_core::AppError> {
    let mw: MaintenanceWindow = sqlx::query_as("SELECT * FROM maintenance_windows WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Maintenance window not found".to_string()))?;
    Ok(Json(mw))
}

async fn update_window(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWindowRequest>,
) -> Result<Json<MaintenanceWindow>, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    let mw: MaintenanceWindow = sqlx::query_as("UPDATE maintenance_windows SET label = COALESCE($2, label), enabled = COALESCE($3, enabled), updated_at = NOW() WHERE id = $1 RETURNING *").bind(id).bind(&req.label).bind(req.enabled).fetch_optional(&state.db).await?.ok_or_else(|| fw_core::AppError::NotFound("Maintenance window not found".to_string()))?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "maintenance_window_updated",
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&mw.id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(Json(mw))
}

async fn delete_window(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM maintenance_windows WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "maintenance_window_deleted",
        Some(auth.user_id),
        Some(&auth.username),
        Some("maintenance_window"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateWindowRequest {
    pub host_id: Uuid,
    pub label: String,
    pub recurrence: String,
    pub start_at: chrono::DateTime<chrono::Utc>,
    pub duration_minutes: Option<i32>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateWindowRequest {
    pub label: Option<String>,
    pub enabled: Option<bool>,
}
