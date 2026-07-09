//! Certificates — list, download, revoke.

use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::Certificate;
use uuid::Uuid;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_certs))
        .route("/{id}", get(get_cert))
        .route("/{id}/revoke", post(revoke_cert))
}

async fn list_certs(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<Certificate>>, fw_core::AppError> {
    let certs: Vec<Certificate> =
        sqlx::query_as("SELECT * FROM certificates ORDER BY issued_at DESC LIMIT 50")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(certs))
}

async fn get_cert(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Certificate>, fw_core::AppError> {
    let cert: Certificate = sqlx::query_as("SELECT * FROM certificates WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| fw_core::AppError::NotFound("Certificate not found".to_string()))?;
    Ok(Json(cert))
}

async fn revoke_cert(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("UPDATE certificates SET status = 'revoked', revoked_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "certificate_revoked",
        Some(auth.user_id),
        Some(&auth.username),
        Some("certificate"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}
