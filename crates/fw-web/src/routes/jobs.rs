//! Jobs — list, get, cancel, rollback.

use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::FirewallJob;
use uuid::Uuid;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_jobs))
        .route("/{id}", get(get_job))
        .route("/{id}/cancel", post(cancel_job))
        .route("/{id}/rollback", post(rollback_job))
}

async fn list_jobs(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<FirewallJob>>, fw_core::AppError> {
    let jobs: Vec<FirewallJob> =
        sqlx::query_as("SELECT * FROM firewall_jobs ORDER BY created_at DESC LIMIT 50")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(jobs))
}

async fn get_job(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FirewallJob>, fw_core::AppError> {
    let job: FirewallJob = sqlx::query_as("SELECT * FROM firewall_jobs WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Job not found".to_string()))?;
    Ok(Json(job))
}

async fn cancel_job(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    sqlx::query("UPDATE firewall_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1 AND status IN ('queued', 'pending')").bind(id).execute(&state.db).await?;
    Ok(StatusCode::OK)
}

async fn rollback_job(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }
    let _ = fw_core::audit::log_event(
        &state.db,
        "firewall_job_rollback",
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}
