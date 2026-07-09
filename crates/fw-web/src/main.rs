use fw_core::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_web=debug,fw_core=debug,info".into()),
        )
        .init();

    let config = AppConfig::load()?;
    let db = fw_core::db::init_pool(&config.database.url).await?;
    fw_core::db::run_migrations(&db).await?;

    // Bootstrap admin password if needed
    fw_web::bootstrap_admin_password(&db).await;

    // Load JWT keys
    let signing_key_pem = fw_auth::jwt::load_signing_key(&config.security.jwt_signing_key_path)?;
    let auth_config = std::sync::Arc::new(fw_auth::rbac::AuthConfig::new(
        fw_auth::jwt::load_verify_key(&config.security.jwt_verify_key_path)?,
        &config.security.ip_whitelist,
        &config.security.trusted_proxies,
    ));

    // Initialize CA
    let ca = std::sync::Arc::new(fw_ca::CertAuthority::init(
        "/etc/firewall-manager/ca".to_string(),
        &db,
    ));

    let state = fw_web::AppState {
        db,
        config: std::sync::Arc::new(config.clone()),
        signing_key_pem,
        auth_config,
        ws_tickets: std::sync::Arc::new(dashmap::DashMap::new()),
        ca,
        approved_enrollments: std::sync::Arc::new(dashmap::DashMap::new()),
    };

    let router = fw_web::build_router(state);
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("fw-web listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
