//! Settings — IP whitelist, trusted proxies, OIDC, SMTP.

use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route(
            "/ip-whitelist",
            get(get_ip_whitelist).put(update_ip_whitelist),
        )
        .route(
            "/trusted-proxies",
            get(get_trusted_proxies).put(update_trusted_proxies),
        )
        .route("/oidc", get(get_oidc_config).put(update_oidc_config))
        .route("/smtp", get(get_smtp_config).put(update_smtp_config))
}

async fn get_ip_whitelist(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    let whitelist: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'ip_whitelist'")
            .fetch_optional(&state.db)
            .await?;
    let entries: Vec<String> = whitelist
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Ok(Json(serde_json::json!({ "ip_whitelist": entries })))
}

async fn update_ip_whitelist(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<UpdateListRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    let json = serde_json::to_string(&req.entries).unwrap_or_default();
    sqlx::query("INSERT INTO system_config (key, value, updated_at) VALUES ('ip_whitelist', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()").bind(&json).execute(&state.db).await?;
    state.auth_config.update_ip_whitelist(req.entries).await;
    let _ = fw_core::audit::log_event(
        &state.db,
        "config_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("settings"),
        Some("ip_whitelist"),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

async fn get_trusted_proxies(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    let proxies: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'trusted_proxies'")
            .fetch_optional(&state.db)
            .await?;
    let entries: Vec<String> = proxies
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Ok(Json(serde_json::json!({ "trusted_proxies": entries })))
}

async fn update_trusted_proxies(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<UpdateListRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    let json = serde_json::to_string(&req.entries).unwrap_or_default();
    sqlx::query("INSERT INTO system_config (key, value, updated_at) VALUES ('trusted_proxies', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()").bind(&json).execute(&state.db).await?;
    state.auth_config.update_trusted_proxies(req.entries).await;
    Ok(StatusCode::OK)
}

async fn get_oidc_config(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    let row: Option<(bool, String, String, String, String)> = sqlx::query_as("SELECT enabled, provider_type, display_name, discovery_url, client_id FROM oidc_config WHERE id = 1").fetch_optional(&state.db).await?;
    match row {
        Some((enabled, ptype, name, url, cid)) => Ok(Json(
            serde_json::json!({ "enabled": enabled, "provider_type": ptype, "display_name": name, "discovery_url": url, "client_id": cid }),
        )),
        None => Ok(Json(serde_json::json!({ "enabled": false }))),
    }
}

async fn update_oidc_config(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    let _ = fw_core::audit::log_event(
        &state.db,
        "config_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("settings"),
        Some("oidc"),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

async fn get_smtp_config(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    let enabled: String =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'smtp_enabled'")
            .fetch_optional(&state.db)
            .await?
            .unwrap_or_default();
    let host: String =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'smtp_host'")
            .fetch_optional(&state.db)
            .await?
            .unwrap_or_default();
    Ok(Json(
        serde_json::json!({ "enabled": enabled == "true", "host": host }),
    ))
}

async fn update_smtp_config(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(_req): Json<serde_json::Value>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    let _ = fw_core::audit::log_event(
        &state.db,
        "config_changed",
        Some(auth.user_id),
        Some(&auth.username),
        Some("settings"),
        Some("smtp"),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateListRequest {
    pub entries: Vec<String>,
}
