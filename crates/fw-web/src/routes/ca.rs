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
    // The imported upstream sub-CA chain, when one is configured (config file
    // paths, loaded at startup). Empty when the self-generated root issues.
    let issuing_chain = state.ca.issuing_chain_pems();
    Ok(Json(serde_json::json!({
        "root_ca": root_cert.is_some(),
        "root_ca_pem": root_cert,
        "issuing_ca": issuing_chain.is_some(),
        "issuing_chain_pem": issuing_chain.map(|c| c.to_vec()),
    })))
}

async fn get_crl(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    // Generated on demand from the `certificates` table (same call the agent
    // verifier and the public /api/v1/pki/crl.pem endpoint use); a small
    // query at LHFM's scale. One CRL per issuing CA (self-root for legacy
    // rows, imported sub-CA when configured). The same CRLs are also
    // available unauthenticated at /api/v1/pki/crl.pem for consumers without
    // a manager login.
    let crls = state
        .ca
        .generate_crls(&state.db)
        .await
        .map_err(|e| fw_core::AppError::Internal(format!("CRL generation failed: {e}")))?;
    Ok(Json(serde_json::json!({ "crl_pems": crls })))
}
