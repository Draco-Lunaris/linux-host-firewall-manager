mod routes;

use axum::Router;
use fw_core::AppConfig;
use std::sync::Arc;

pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<AppConfig>,
    pub signing_key_pem: String,
    pub auth_config: fw_auth::AuthConfig,
}

pub async fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/status/health",
            axum::routing::get(routes::health::health_handler),
        )
        .with_state(state)
}

pub async fn run() -> anyhow::Result<()> {
    let config = AppConfig::load()?;
    let db = fw_core::db::init_pool(&config.database.url).await?;
    fw_core::db::run_migrations(&db).await?;

    let signing_key_pem = fw_auth::jwt::load_signing_key(&config.security.jwt_signing_key_path)?;
    let auth_config = fw_auth::AuthConfig {
        verify_key_pem: fw_auth::jwt::load_verify_key(&config.security.jwt_verify_key_path)?,
        ip_whitelist: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        trusted_proxies: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
    };

    let state = Arc::new(AppState {
        db,
        config: std::sync::Arc::new(config.clone()),
        signing_key_pem,
        auth_config,
    });

    let router = build_router(state).await;
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("fw-web listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
