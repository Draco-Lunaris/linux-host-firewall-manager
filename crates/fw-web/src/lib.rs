#![allow(clippy::type_complexity)]
//! fw-web — Linux Host Firewall Manager web server (library crate).

pub mod routes;
pub mod secret_key;

use axum::{middleware, routing::get, Router};
use dashmap::DashMap;
use fw_auth::rbac::{require_auth, AuthConfig};
use fw_core::{config::AppConfig, request_id::request_id_middleware};
use rand::Rng;
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};

/// Placeholder Argon2id hash prefix used in the seed admin migration.
const ADMIN_PLACEHOLDER_HASH_PREFIX: &str = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA";

/// Bootstrap the default admin account with a random password.
pub async fn bootstrap_admin_password(pool: &sqlx::PgPool) {
    let result: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE username = 'admin'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let current_hash = match result {
        Some(h) => h,
        None => return,
    };

    if !current_hash.starts_with(ADMIN_PLACEHOLDER_HASH_PREFIX) {
        return;
    }

    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();

    let new_hash = match fw_auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash bootstrap admin password");
            return;
        }
    };

    let rows = sqlx::query(
        r#"UPDATE users SET password_hash = $1
           WHERE username = 'admin'
             AND password_hash LIKE '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA%'"#,
    )
    .bind(&new_hash)
    .execute(pool)
    .await;

    if let Ok(result) = rows {
        if result.rows_affected() == 1 {
            eprintln!();
            eprintln!("========================================");
            eprintln!("  INITIAL ADMIN PASSWORD (shown once)");
            eprintln!("  Username: admin");
            eprintln!("  Password: {}", password);
            eprintln!("========================================");
            eprintln!();
            tracing::info!("Bootstrap admin password generated and set");
        }
    }
}

/// Shared application state threaded through Axum.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<AppConfig>,
    pub signing_key_pem: String,
    pub auth_config: Arc<AuthConfig>,
    pub ws_tickets: Arc<DashMap<String, WsTicket>>,
    pub ca: Arc<fw_ca::CertAuthority>,
    pub approved_enrollments: Arc<DashMap<String, ApprovedEntry>>,
}
#[derive(Debug, Clone)]
pub struct WsTicket {
    pub user_id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Approved enrollment PKI bundle cache entry (single-use, 10-min TTL).
#[derive(Debug, Clone)]
pub struct ApprovedEntry {
    pub pki_bundle: fw_core::models::PkiBundle,
    pub host_id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Construct the full Axum router.
pub fn build_router(state: AppState) -> Router<()> {
    let state = std::sync::Arc::new(state);
    let static_dir = state.config.server.static_dir.clone();
    let auth_config = state.auth_config.clone();
    let rl = &state.config.rate_limit;

    let enrollment_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(12_000)
            .burst_size(rl.enrollment_burst)
            .finish()
            .expect("Invalid enrollment governor config"),
    );

    let auth_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(3_000)
            .burst_size(rl.auth_burst)
            .finish()
            .expect("Invalid auth governor config"),
    );

    let api_governor = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_millisecond(500)
            .burst_size(rl.api_burst)
            .finish()
            .expect("Invalid API governor config"),
    );

    let enrollment_router =
        routes::enrollment::router().layer(GovernorLayer::new(enrollment_governor));

    let auth_public_router =
        routes::auth::public_router().layer(GovernorLayer::new(Arc::clone(&auth_governor)));

    let protected_api = Router::new()
        .route("/status/fleet", get(routes::health::fleet_status_handler))
        .nest("/auth", routes::auth::protected_router())
        .nest("/hosts", routes::hosts::router())
        .nest("/groups", routes::groups::router())
        .nest("/users", routes::users::router())
        .nest("/rules", routes::rules::router())
        .nest("/policy-sets", routes::policy_sets::router())
        .nest("/deployment", routes::deployment::router())
        .nest("/jobs", routes::jobs::router())
        .nest(
            "/maintenance-windows",
            routes::maintenance_windows::router(),
        )
        .nest("/ca", routes::ca::router())
        .nest("/certificates", routes::certificates::router())
        .nest("/settings", routes::settings::router())
        .nest("/admin", routes::enrollment::admin_router())
        .layer(GovernorLayer::new(api_governor))
        .route_layer(middleware::from_fn(move |req, next| {
            let auth_config = auth_config.clone();
            require_auth(auth_config, req, next)
        }));

    Router::new()
        .route("/status/health", get(routes::health::health_handler))
        .nest("/api/v1/agent", routes::agent_api::router())
        .nest("/api/v1/auth", auth_public_router)
        .nest("/api/v1", enrollment_router)
        .nest("/api/v1", protected_api)
        .fallback_service(
            ServeDir::new(&static_dir)
                .append_index_html_on_directories(true)
                .fallback(ServeFile::new(format!("{}/index.html", static_dir))),
        )
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Construct the package repository router (served on plain HTTP port 80).
pub fn build_repo_router(_state: &AppState) -> Router {
    let repo_dir = "/var/www/firewall-agent-repo";
    Router::new()
        .nest_service("/apt", ServeDir::new(format!("{repo_dir}/apt")))
        .nest_service("/dnf", ServeDir::new(format!("{repo_dir}/dnf")))
        .nest_service("/apk", ServeDir::new(format!("{repo_dir}/apk")))
        .nest_service("/pacman", ServeDir::new(format!("{repo_dir}/pacman")))
}
