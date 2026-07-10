//! Enrollment routes — 3-phase enrollment with CSR + one-time tokens (SEC-002).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/enroll", post(submit_enrollment))
        .route("/enroll/status/{token}", get(poll_enrollment_status))
}

pub fn admin_router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/enrollments", get(list_enrollments))
        .route("/enrollments/{id}/approve", post(approve_enrollment))
        .route("/enrollments/{id}/deny", post(deny_enrollment))
        .route("/enrollment-tokens", get(list_tokens).post(create_token))
        .route("/enrollment-tokens/{hash}", post(revoke_token))
}

#[derive(Debug, Deserialize)]
pub struct SubmitEnrollmentRequest {
    pub token: String,
    pub csr: String,
    pub fqdn: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub os_details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct EnrollmentStatusResponse {
    pub status: String,
    pub pki_bundle: Option<fw_core::models::PkiBundle>,
}

async fn submit_enrollment(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<SubmitEnrollmentRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), fw_core::AppError> {
    // Validate token
    let token_hash = hex::encode(sha2::Sha256::digest(req.token.as_bytes()));
    let token_row: Option<(
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as("SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash = $1")
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await?;

    match token_row {
        Some((expires_at, used_at)) => {
            if used_at.is_some() {
                return Err(fw_core::AppError::BadRequest(
                    "Token already used".to_string(),
                ));
            }
            if expires_at < chrono::Utc::now() {
                return Err(fw_core::AppError::BadRequest("Token expired".to_string()));
            }
            // Validate FQDN matches token
            let token_fqdn: Option<String> =
                sqlx::query_scalar("SELECT host_fqdn FROM enrollment_tokens WHERE token_hash = $1")
                    .bind(&token_hash)
                    .fetch_optional(&state.db)
                    .await?;
            if token_fqdn.as_deref() != Some(&req.fqdn) {
                return Err(fw_core::AppError::BadRequest(
                    "FQDN does not match token".to_string(),
                ));
            }
        }
        None => {
            return Err(fw_core::AppError::BadRequest("Invalid token".to_string()));
        }
    }

    // Mark token as used
    let _ = sqlx::query("UPDATE enrollment_tokens SET used_at = NOW() WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&state.db)
        .await;

    // Create enrollment request
    let machine_id = format!("{}-{}", req.fqdn, req.ip_address);
    let polling_token = Uuid::new_v4().to_string();
    let polling_hash = fw_auth::password::hash_password(&polling_token)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO enrollment_requests (machine_id, fqdn, ip_address, hostname, os_details, polling_token)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (machine_id) DO UPDATE SET polling_token = $6, created_at = NOW()",
    )
    .bind(&machine_id)
    .bind(&req.fqdn)
    .bind(&req.ip_address)
    .bind(&req.hostname)
    .bind(&req.os_details)
    .bind(&polling_hash)
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "enrollment_token_used",
        None,
        None,
        Some("enrollment"),
        Some(&req.fqdn),
        serde_json::json!({ "fqdn": req.fqdn, "ip": req.ip_address }),
        Some(&req.ip_address),
        None,
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "polling_token": polling_token })),
    ))
}

async fn poll_enrollment_status(
    State(state): State<std::sync::Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, fw_core::AppError> {
    let hash = fw_auth::password::hash_password(&token)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, fqdn FROM enrollment_requests WHERE polling_token = $1 AND expires_at > NOW()",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((_id, _fqdn)) => {
            // Check if approved
            if let Some(entry) = state.approved_enrollments.get(&hash) {
                let bundle = entry.pki_bundle.clone();
                state.approved_enrollments.remove(&hash);
                return Ok(Json(EnrollmentStatusResponse {
                    status: "approved".to_string(),
                    pki_bundle: Some(bundle),
                }));
            }
            Ok(Json(EnrollmentStatusResponse {
                status: "pending".to_string(),
                pki_bundle: None,
            }))
        }
        None => Err(fw_core::AppError::NotFound(
            "Enrollment not found or expired".to_string(),
        )),
    }
}

async fn list_enrollments(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<fw_core::models::EnrollmentRequest>>, fw_core::AppError> {
    let requests: Vec<fw_core::models::EnrollmentRequest> = sqlx::query_as(
        "SELECT * FROM enrollment_requests WHERE expires_at > NOW() ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(requests))
}

async fn approve_enrollment(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }

    // Fetch enrollment request
    let req: Option<(String, String, Option<String>, serde_json::Value, String)> = sqlx::query_as(
        "SELECT fqdn, ip_address, hostname, os_details, polling_token FROM enrollment_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;

    let (fqdn, ip, hostname, os_details, polling_token) =
        req.ok_or_else(|| fw_core::AppError::NotFound("Enrollment request not found".to_string()))?;

    // Check FQDN/IP collision
    let collision: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE fqdn = $1 AND ip_address = $2")
            .bind(&fqdn)
            .bind(&ip)
            .fetch_one(&state.db)
            .await?;

    if collision > 0 {
        return Err(fw_core::AppError::Conflict(
            "Host already registered".to_string(),
        ));
    }

    // Insert host
    let host_id: Uuid = sqlx::query_scalar(
        "INSERT INTO hosts (fqdn, ip_address, display_name, os_name) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&fqdn)
    .bind(&ip)
    .bind(hostname.as_deref().unwrap_or(&fqdn))
    .bind(os_details.get("os_name").and_then(|v| v.as_str()).unwrap_or("unknown"))
    .fetch_one(&state.db)
    .await?;

    // Create default host config overrides for the pull model
    let _ = sqlx::query(
        "INSERT INTO host_config_overrides (host_id, check_in_interval_secs, push_enabled, safe_mode_enabled, config_version)
         VALUES ($1, 900, TRUE, FALSE, 1) ON CONFLICT (host_id) DO NOTHING",
    )
    .bind(host_id)
    .execute(&state.db)
    .await;

    // Build the manager check-in URL
    let manager_check_in_url = format!(
        "https://{}:{}/api/v1/agent/check-in",
        state.config.server.host,
        state.config.server.port
    );

    // Issue cert (stub — CA implementation will fill this in)
    // For now, create a placeholder PKI bundle with pull config
    let pki_bundle = fw_core::models::PkiBundle {
        ca_chain: vec!["PLACEHOLDER_CA".to_string()],
        server_cert: "PLACEHOLDER_CERT".to_string(),
        crl_pem: None,
        repo_config: None,
        pull_config: Some(fw_core::models::PullConfigBundle {
            check_in_interval_secs: 900,
            push_enabled: true,
            config_version: 1,
            manager_check_in_url,
        }),
    };

    // Cache the bundle for single-retrieval
    state.approved_enrollments.insert(
        polling_token.clone(),
        crate::ApprovedEntry {
            pki_bundle,
            host_id,
            created_at: chrono::Utc::now(),
        },
    );

    // Delete enrollment request
    sqlx::query("DELETE FROM enrollment_requests WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "host_enrolled",
        Some(auth.user_id),
        Some(&auth.username),
        Some("host"),
        Some(&host_id.to_string()),
        serde_json::json!({ "fqdn": fqdn, "ip": ip }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::OK)
}

async fn deny_enrollment(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM enrollment_requests WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::OK)
}

async fn list_tokens(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>, fw_core::AppError> {
    let tokens: Vec<(String, String, Option<String>, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT host_fqdn, token_hash, host_ip, expires_at, used_at FROM enrollment_tokens WHERE used_at IS NULL AND revoked_at IS NULL ORDER BY expires_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let result: Vec<serde_json::Value> = tokens
        .iter()
        .map(|(fqdn, hash, ip, expires, used)| {
            serde_json::json!({
                "host_fqdn": fqdn,
                "token_hash_prefix": &hash[..16],
                "host_ip": ip,
                "expires_at": expires,
                "used_at": used,
            })
        })
        .collect();
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub host_fqdn: String,
    pub host_ip: Option<String>,
    pub ttl_hours: Option<i64>,
}

async fn create_token(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<serde_json::Value>, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }

    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let token_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    let ttl_hours = req.ttl_hours.unwrap_or(24);

    sqlx::query(
        "INSERT INTO enrollment_tokens (token_hash, host_fqdn, host_ip, created_by, expires_at) VALUES ($1, $2, $3, $4, NOW() + $5::bigint * INTERVAL '1 hour')",
    )
    .bind(&token_hash)
    .bind(&req.host_fqdn)
    .bind(&req.host_ip)
    .bind(auth.user_id)
    .bind(ttl_hours)
    .execute(&state.db)
    .await?;

    let _ = fw_core::audit::log_event(
        &state.db,
        "enrollment_token_issued",
        Some(auth.user_id),
        Some(&auth.username),
        Some("enrollment"),
        Some(&req.host_fqdn),
        serde_json::json!({ "fqdn": req.host_fqdn, "ttl_hours": ttl_hours }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(Json(serde_json::json!({
        "token": token,
        "host_fqdn": req.host_fqdn,
        "expires_in_hours": ttl_hours,
        "warning": "Token shown once. Deliver out-of-band to the host operator."
    })))
}

async fn revoke_token(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(hash): Path<String>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("UPDATE enrollment_tokens SET revoked_at = NOW() WHERE token_hash = $1")
        .bind(&hash)
        .execute(&state.db)
        .await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "enrollment_token_revoked",
        Some(auth.user_id),
        Some(&auth.username),
        Some("enrollment"),
        Some(&hash),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::OK)
}
