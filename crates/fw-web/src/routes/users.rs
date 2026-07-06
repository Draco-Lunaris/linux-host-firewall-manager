//! Users CRUD.

use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use fw_core::models::User;
use uuid::Uuid;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/{id}", get(get_user).put(update_user).delete(delete_user))
}

async fn list_users(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<User>>, fw_core::AppError> {
    let users: Vec<User> = sqlx::query_as("SELECT id, username, display_name, email, role, auth_provider, mfa_enabled, is_active, force_password_reset, last_login_at, created_at, updated_at, failed_login_attempts, locked_until FROM users ORDER BY username").fetch_all(&state.db).await?;
    Ok(Json(users))
}

async fn create_user(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<User>), fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    fw_auth::validate_password_strength(&req.password)?;
    let hash = fw_auth::hash_password(&req.password)
        .map_err(|e| fw_core::AppError::Internal(e.to_string()))?;
    let user: User = sqlx::query_as("INSERT INTO users (username, display_name, email, role, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, display_name, email, role, auth_provider, mfa_enabled, is_active, force_password_reset, last_login_at, created_at, updated_at, failed_login_attempts, locked_until").bind(&req.username).bind(&req.display_name).bind(&req.email).bind(&req.role).bind(&hash).fetch_one(&state.db).await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "user_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&user.id.to_string()),
        serde_json::json!({"username": user.username}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn get_user(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, fw_core::AppError> {
    let user: User = sqlx::query_as("SELECT id, username, display_name, email, role, auth_provider, mfa_enabled, is_active, force_password_reset, last_login_at, created_at, updated_at, failed_login_attempts, locked_until FROM users WHERE id = $1").bind(id).fetch_optional(&state.db).await?.ok_or_else(|| fw_core::AppError::NotFound("User not found".to_string()))?;
    Ok(Json(user))
}

async fn update_user(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<User>, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    let user: User = sqlx::query_as("UPDATE users SET display_name = COALESCE($2, display_name), email = COALESCE($3, email), role = COALESCE($4, role), is_active = COALESCE($5, is_active), updated_at = NOW() WHERE id = $1 RETURNING id, username, display_name, email, role, auth_provider, mfa_enabled, is_active, force_password_reset, last_login_at, created_at, updated_at, failed_login_attempts, locked_until").bind(id).bind(&req.display_name).bind(&req.email).bind(&req.role).bind(req.is_active).fetch_optional(&state.db).await?.ok_or_else(|| fw_core::AppError::NotFound("User not found".to_string()))?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "user_updated",
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&user.id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, fw_core::AppError> {
    if !auth.role.is_admin() {
        return Err(fw_core::AppError::Forbidden(
            "Admin role required".to_string(),
        ));
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    let _ = fw_core::audit::log_event(
        &state.db,
        "user_deleted",
        Some(auth.user_id),
        Some(&auth.username),
        Some("user"),
        Some(&id.to_string()),
        serde_json::json!({}),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub password: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}
