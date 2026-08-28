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

use super::settings::global_check_in_interval;

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
    /// The manager-assigned host_id (present on approval). The agent persists
    /// this into its config so the pull loop knows its own identity for
    /// check-in. The cert CN remains the authoritative identity at mTLS time.
    pub host_id: Option<String>,
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
    // Deterministic hash (SHA-256) so the status poll can look the request up by
    // re-hashing the presented token. Argon2 (hash_password) is salted and would
    // never match on re-computation.
    let polling_hash = hex::encode(sha2::Sha256::digest(polling_token.as_bytes()));

    sqlx::query(
        "INSERT INTO enrollment_requests (machine_id, fqdn, ip_address, hostname, os_details, polling_token, csr)
         VALUES ($1, $2, $3::inet, $4, $5, $6, $7)
         ON CONFLICT (machine_id) DO UPDATE SET polling_token = $6, csr = $7, created_at = NOW()",
    )
    .bind(&machine_id)
    .bind(&req.fqdn)
    .bind(&req.ip_address)
    .bind(&req.hostname)
    .bind(&req.os_details)
    .bind(&polling_hash)
    .bind(&req.csr)
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
    let hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));

    // Approved? The approve flow caches the bundle and then DELETES the
    // enrollment_requests row, so check the cache before the row lookup —
    // otherwise the agent's post-approval poll would 404 and never receive
    // its cert bundle.
    //
    // Use `remove` (returns the value, no held guard) rather than `get` then
    // `remove`: DashMap shards by key, so `get` returns a `Ref` holding a
    // read-lock on the shard, and calling `remove` on the same key while that
    // guard is live deadlocks the worker thread (write-lock waiting on the
    // held read-lock). The single-retrieval semantics are preserved — the
    // entry is removed atomically, so a concurrent poll never sees it twice.
    if let Some((_, entry)) = state.approved_enrollments.remove(&hash) {
        return Ok(Json(EnrollmentStatusResponse {
            status: "approved".to_string(),
            pki_bundle: Some(entry.pki_bundle),
            host_id: Some(entry.host_id.to_string()),
        }));
    }

    // Pending? (Request still exists and not expired.)
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, fqdn FROM enrollment_requests WHERE polling_token = $1 AND expires_at > NOW()",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((_id, _fqdn)) => Ok(Json(EnrollmentStatusResponse {
            status: "pending".to_string(),
            pki_bundle: None,
            host_id: None,
        })),
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
        "SELECT id, machine_id, fqdn, ip_address::text, hostname, os_details, polling_token, csr, created_at, expires_at
         FROM enrollment_requests WHERE expires_at > NOW() ORDER BY created_at DESC",
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
    let req: Option<(String, String, Option<String>, serde_json::Value, String, Option<String>)> =
        sqlx::query_as(
            "SELECT fqdn, ip_address::text, hostname, os_details, polling_token, csr FROM enrollment_requests WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await?;

    let (fqdn, ip, hostname, os_details, polling_token, csr) =
        req.ok_or_else(|| fw_core::AppError::NotFound("Enrollment request not found".to_string()))?;

    // Check FQDN/IP collision
    let collision: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE fqdn = $1 AND ip_address = $2::inet")
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
        "INSERT INTO hosts (fqdn, ip_address, display_name, os_name) VALUES ($1, $2::inet, $3, $4) RETURNING id",
    )
    .bind(&fqdn)
    .bind(&ip)
    .bind(hostname.as_deref().unwrap_or(&fqdn))
    .bind(os_details.get("os_name").and_then(|v| v.as_str()).unwrap_or("unknown"))
    .fetch_one(&state.db)
    .await?;

    // Create default host config overrides for the pull model
    // Seed this host's config overrides from the fleet-wide polling interval
    // (set via the manager Settings UI). Using the global value here — not a
    // hardcoded 900 — means a newly-enrolled host starts on the global
    // interval instead of waiting for the next Settings save to propagate.
    let check_in_interval = global_check_in_interval(&state.db).await;
    let _ = sqlx::query(
        "INSERT INTO host_config_overrides (host_id, check_in_interval_secs, push_enabled, safe_mode_enabled, config_version)
         VALUES ($1, $2, TRUE, FALSE, 1) ON CONFLICT (host_id) DO NOTHING",
    )
    .bind(host_id)
    .bind(check_in_interval)
    .execute(&state.db)
    .await;

    // Build the agent API base URL. The agent API lives on the dedicated mTLS
    // agent_port (8443), not the human-UI port (443) — handing out the human-UI
    // port would send the agent to a listener that never mounts the agent API.
    // This is a *base* URL (scheme://host:port); the agent appends the endpoint
    // paths so all four agent endpoints (check-in, check-in/result, policy,
    // events) share it.
    let manager_agent_url = format!(
        "https://{}:{}",
        state.config.server.host, state.config.server.agent_port
    );

    // Sign the agent's CSR with the manager CA, binding the cert identity to host_id.
    // The manager rewrites the subject CN to the assigned host_id (not the agent's FQDN),
    // so the cert — not the request body — is the host identity.
    let csr = csr.ok_or_else(|| {
        fw_core::AppError::BadRequest("Enrollment request has no CSR".to_string())
    })?;
    let signed = state
        .ca
        .sign_csr(&csr, host_id)
        .map_err(|e| fw_core::AppError::Internal(format!("CA sign failed: {e}")))?;

    // Persist the leaf cert so it can be revoked by serial and fed into the CRL
    // (the 8443 verifier rejects revoked client certs at the TLS handshake).
    // Expiry mirrors sign_csr's HOST_CERT_VALIDITY_YEARS (365 days).
    sqlx::query(
        "INSERT INTO certificates (host_id, serial_number, common_name, status, issued_at, expires_at, cert_pem, ca_tier)
         VALUES ($1, $2, $3, 'active', NOW(), NOW() + INTERVAL '365 days', $4, 'leaf')",
    )
    .bind(host_id)
    .bind(&signed.serial_hex)
    .bind(host_id.to_string())
    .bind(&signed.cert_pem)
    .execute(&state.db)
    .await?;
    let pki_bundle = fw_core::models::PkiBundle {
        ca_chain: signed.ca_chain,
        server_cert: signed.cert_pem,
        crl_pem: signed.crl_pem,
        pull_config: Some(fw_core::models::PullConfigBundle {
            check_in_interval_secs: check_in_interval,
            push_enabled: true,
            config_version: 1,
            manager_agent_url,
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
        "SELECT host_fqdn, token_hash, host_ip::text, expires_at, used_at FROM enrollment_tokens WHERE used_at IS NULL AND revoked_at IS NULL ORDER BY expires_at DESC",
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
        "INSERT INTO enrollment_tokens (token_hash, host_fqdn, host_ip, created_by, expires_at) VALUES ($1, $2, $3::inet, $4, NOW() + $5::bigint * INTERVAL '1 hour')",
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
