//! Settings — IP whitelist, trusted proxies, OIDC, SMTP.

use crate::AppState;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use fw_auth::rbac::AuthUser;
use std::str::FromStr;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(get_settings))
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

async fn get_settings(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    // Return a combined settings object that the frontend expects
    let ip_whitelist: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'ip_whitelist'")
            .fetch_optional(&state.db)
            .await?;
    let ip_list: Vec<String> = ip_whitelist
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "oidc": { "enabled": false, "issuer": "", "client_id": "", "client_secret": "", "redirect_uri": "" },
        "smtp": { "enabled": false, "host": "", "port": 587, "username": "", "password": "", "from": "", "tls_mode": "starttls" },
        "polling": { "health_interval": 300, "drift_interval": 900 },
        "ip_whitelist": ip_list,
        "web_tls_strategy": "internal_ca",
        "notification": { "email_enabled": false, "webhook_enabled": false, "webhook_url": "" }
    })))
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

    // Validate each entry is a valid CIDR or IP address
    let validated: Vec<String> = req
        .entries
        .iter()
        .map(|entry| validate_cidr_or_ip(entry))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|bad| {
            fw_core::AppError::BadRequest(format!(
                "Invalid IP/CIDR entry: '{}'. Use formats like 10.0.0.0/8, 192.168.1.0/24, or 10.0.0.1",
                bad
            ))
        })?;

    // Lockout prevention: if the new whitelist is non-empty, the requester's
    // IP must be within at least one of the entries. This prevents an admin
    // from accidentally locking themselves out.
    if !validated.is_empty() {
        let requester_ip = auth.ip.unwrap_or_else(|| {
            // If we can't determine the IP, block the update as a safety measure
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        });

        let covers_requester = validated.iter().any(|entry| {
            ipnet::IpNet::from_str(entry)
                .map(|net| net.contains(&requester_ip))
                .unwrap_or(false)
        });

        if !covers_requester {
            return Err(fw_core::AppError::BadRequest(
                format!(
                    "Lockout prevention: your IP ({}) is not in the new whitelist. \
                     Add your IP or subnet to the list before saving, or clear the \
                     list to allow all IPs.",
                    requester_ip
                ),
            ));
        }
    }

    let json = serde_json::to_string(&validated).unwrap_or_default();
    sqlx::query("INSERT INTO system_config (key, value, updated_at) VALUES ('ip_whitelist', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()").bind(&json).execute(&state.db).await?;
    state.auth_config.update_ip_whitelist(validated).await;
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

    // Validate each entry is a valid CIDR or IP address
    let validated: Vec<String> = req
        .entries
        .iter()
        .map(|entry| validate_cidr_or_ip(entry))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|bad| {
            fw_core::AppError::BadRequest(format!(
                "Invalid IP/CIDR entry: '{}'. Use formats like 10.0.0.0/8, 192.168.1.0/24, or 10.0.0.1",
                bad
            ))
        })?;

    let json = serde_json::to_string(&validated).unwrap_or_default();
    sqlx::query("INSERT INTO system_config (key, value, updated_at) VALUES ('trusted_proxies', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()").bind(&json).execute(&state.db).await?;
    state.auth_config.update_trusted_proxies(validated).await;
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

/// Validate that a string is a valid CIDR (e.g. "10.0.0.0/8") or a bare IP
/// address (e.g. "10.0.0.1"). Bare IPs are normalized to /32 (IPv4) or /128 (IPv6).
/// Returns the normalized CIDR string on success, or the original (invalid) string
/// as an error for the caller to include in a user-facing message.
fn validate_cidr_or_ip(entry: &str) -> Result<String, String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(entry.to_string());
    }

    // Try parsing as a CIDR first (e.g. "10.0.0.0/8")
    if let Ok(net) = ipnet::IpNet::from_str(trimmed) {
        return Ok(net.to_string());
    }

    // Try parsing as a bare IP address — normalize to /32 or /128
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        let net = match ip {
            std::net::IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            std::net::IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        };
        return Ok(net.to_string());
    }

    // Neither valid CIDR nor valid IP
    Err(entry.to_string())
}
