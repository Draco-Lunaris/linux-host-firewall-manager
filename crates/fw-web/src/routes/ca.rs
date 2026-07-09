//! CA routes — root CA info, intermediate CA info, CRL download.

use crate::AppState;
use axum::{extract::State, routing::get, Json, Router};
use fw_auth::rbac::AuthUser;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(get_ca_info))
        .route("/crl", get(get_crl))
}

async fn get_ca_info(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    let root_cert: Option<String> =
        sqlx::query_scalar("SELECT cert_pem FROM certificates WHERE ca_tier = 'root' LIMIT 1")
            .fetch_optional(&state.db)
            .await?;
    let intermediate_cert: Option<String> = sqlx::query_scalar("SELECT cert_pem FROM certificates WHERE ca_tier = 'intermediate' AND status = 'active' LIMIT 1").fetch_optional(&state.db).await?;
    Ok(Json(serde_json::json!({
        "root_ca": root_cert.is_some(),
        "intermediate_ca": intermediate_cert.is_some(),
        "root_ca_pem": root_cert,
        "intermediate_ca_pem": intermediate_cert,
    })))
}

async fn get_crl(
    State(_state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    Ok(Json(
        serde_json::json!({ "crl_pem": null, "message": "CRL not yet implemented" }),
    ))
}
