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
    let result =
        sqlx::query("UPDATE certificates SET status = 'revoked', revoked_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await?;
    if result.rows_affected() == 0 {
        return Err(fw_core::AppError::NotFound(
            "Certificate not found".to_string(),
        ));
    }
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

    // Hot-swap the agent listener's client verifier with a freshly generated
    // CRL so the revocation takes effect on the next handshake, without a
    // restart. If the rebuild fails the revocation still stands in the DB and
    // is enforced at the next restart — never fail the API call over it.
    if let Some(shared) = &state.agent_tls_acceptor {
        match crate::agent_cert::build_agent_tls_config(&state.ca, &state.db, &state.config).await {
            Ok(config) => {
                crate::agent_listener::swap_shared_acceptor(shared, config);
                tracing::info!(cert_id = %id, "agent TLS verifier reloaded with refreshed CRL");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    %id,
                    "CRL hot-swap failed — revocation takes effect at next restart"
                );
            }
        }
    }

    Ok(StatusCode::OK)
}
