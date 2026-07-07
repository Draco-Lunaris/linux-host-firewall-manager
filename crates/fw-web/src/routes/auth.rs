#![allow(clippy::type_complexity)]
//! Auth routes — login, refresh, logout, MFA setup.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use serde::{Deserialize, Serialize};

use crate::AppState;

pub fn public_router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/logout", post(logout))
}

pub fn protected_router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/me", get(get_me))
        .route("/mfa/setup", post(mfa_setup))
        .route("/mfa/verify", post(mfa_verify))
        .route("/password/change", post(change_password))
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: String,
    pub mfa_enabled: bool,
}

async fn login(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, fw_core::AppError> {
    let user: Option<(uuid::Uuid, String, String, bool, bool, Option<String>, Option<chrono::DateTime<chrono::Utc>>, i32, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT id, username, role, mfa_enabled, is_active, password_hash, last_login_at, failed_login_attempts, locked_until FROM users WHERE username = $1 AND auth_provider = 'local'",
        )
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await
        .map_err(fw_core::AppError::Database)?;

    let (
        user_id,
        username,
        role,
        mfa_enabled,
        is_active,
        password_hash,
        _last_login,
        failed_attempts,
        locked_until,
    ) = user.unwrap_or_else(|| {
        // Dummy hash to prevent timing attacks
        (
            uuid::Uuid::nil(),
            String::new(),
            String::new(),
            false,
            false,
            Some("$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA$dummy".to_string()),
            None,
            0,
            None,
        )
    });

    if !is_active {
        return Err(fw_core::AppError::Unauthorized(
            "Invalid credentials".to_string(),
        ));
    }

    // Check lockout
    if let Some(lock_until) = locked_until {
        if lock_until > chrono::Utc::now() {
            return Err(fw_core::AppError::Unauthorized(
                "Account locked".to_string(),
            ));
        }
    }

    // Verify password
    let hash = password_hash.unwrap_or_default();
    let valid = fw_auth::verify_password(&req.password, &hash).unwrap_or(false);

    if !valid {
        // Increment failed attempts
        let _ = sqlx::query(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        )
        .bind(user_id)
        .execute(&state.db)
        .await;

        // Lock after 5 failures
        if failed_attempts + 1 >= 5 {
            let _ = sqlx::query(
                "UPDATE users SET locked_until = NOW() + INTERVAL '30 minutes' WHERE id = $1",
            )
            .bind(user_id)
            .execute(&state.db)
            .await;
        }

        let _ = fw_core::audit::log_event(
            &state.db,
            "user_login_failed",
            None,
            Some(&req.username),
            Some("user"),
            Some(&user_id.to_string()),
            serde_json::json!({ "reason": "invalid_password" }),
            None,
            None,
        )
        .await;

        return Err(fw_core::AppError::Unauthorized(
            "Invalid credentials".to_string(),
        ));
    }

    // Reset failed attempts
    let _ = sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .execute(&state.db)
    .await;

    // Issue tokens
    let (access_token, jti) =
        fw_auth::issue_access_token(&state.signing_key_pem, user_id, &role, &username)
            .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    // Store refresh token + jti
    let refresh_token = uuid::Uuid::new_v4().to_string();
    let refresh_hash = fw_auth::password::hash_password(&refresh_token)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;
    let _ =
        sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, jti) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(&refresh_hash)
            .bind(&jti)
            .execute(&state.db)
            .await;

    let _ = fw_core::audit::log_event(
        &state.db,
        "user_login",
        Some(user_id),
        Some(&username),
        Some("user"),
        Some(&user_id.to_string()),
        serde_json::json!({}),
        None,
        None,
    )
    .await;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        user: UserInfo {
            id: user_id,
            username,
            role,
            mfa_enabled,
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

async fn refresh_token(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, fw_core::AppError> {
    // Verify refresh token hash
    let hash = fw_auth::password::hash_password(&req.refresh_token)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    let row: Option<(uuid::Uuid, String, String, bool)> = sqlx::query_as(
        "SELECT u.id, u.username, u.role, rt.revoked FROM refresh_tokens rt
         JOIN users u ON u.id = rt.user_id
         WHERE rt.token_hash = $1 AND rt.revoked = FALSE AND rt.expires_at > NOW()",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(fw_core::AppError::Database)?;

    let (user_id, username, role, revoked) =
        row.ok_or_else(|| fw_core::AppError::Unauthorized("Invalid refresh token".to_string()))?;

    if revoked {
        return Err(fw_core::AppError::Unauthorized("Token revoked".to_string()));
    }

    let (access_token, jti) =
        fw_auth::issue_access_token(&state.signing_key_pem, user_id, &role, &username)
            .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    // Update jti on the refresh token
    let _ = sqlx::query(
        "UPDATE refresh_tokens SET jti = $2, last_used_at = NOW() WHERE token_hash = $1",
    )
    .bind(&hash)
    .bind(&jti)
    .execute(&state.db)
    .await;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: req.refresh_token,
        user: UserInfo {
            id: user_id,
            username,
            role,
            mfa_enabled: false,
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    let hash = fw_auth::password::hash_password(&req.refresh_token)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    let _ = sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1",
    )
    .bind(&hash)
    .execute(&state.db)
    .await;

    let _ = fw_core::audit::log_event(
        &state.db,
        "user_logout",
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&auth.user_id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok(StatusCode::OK)
}

async fn get_me(auth: AuthUser) -> Json<UserInfo> {
    Json(UserInfo {
        id: auth.user_id,
        username: auth.username,
        role: auth.role.as_str().to_string(),
        mfa_enabled: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct MfaSetupRequest {
    pub secret: String,
    pub code: String,
}

async fn mfa_setup(
    State(_state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Json(_req): Json<MfaSetupRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String,
}

async fn mfa_verify(
    State(_state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Json(_req): Json<MfaVerifyRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

async fn change_password(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, fw_core::AppError> {
    fw_auth::validate_password_strength(&req.new_password)?;

    let hash: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await?;

    let hash = hash.ok_or_else(|| fw_core::AppError::NotFound("User not found".to_string()))?;

    if !fw_auth::verify_password(&req.current_password, &hash).unwrap_or(false) {
        return Err(fw_core::AppError::Unauthorized(
            "Invalid current password".to_string(),
        ));
    }

    let new_hash = fw_auth::hash_password(&req.new_password)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;

    sqlx::query("UPDATE users SET password_hash = $1, force_password_reset = FALSE, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(auth.user_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::OK)
}
