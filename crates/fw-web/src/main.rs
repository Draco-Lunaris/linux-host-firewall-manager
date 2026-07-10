use fw_core::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the default crypto provider for rustls (required since 0.23)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_web=debug,fw_core=debug,fw_auth=debug,info".into()),
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
    let addr: std::net::SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

    // Try to load TLS certificate and key; fall back to plain HTTP if missing.
    let tls_cert = std::path::Path::new(&config.security.web_tls_cert_path);
    let tls_key = std::path::Path::new(&config.security.web_tls_key_path);

    if tls_cert.exists() && tls_key.exists() {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &config.security.web_tls_cert_path,
            &config.security.web_tls_key_path,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load TLS certificates");
            e
        })?;

        tracing::info!(%addr, "fw-web listening (HTTPS)");
        axum_server::bind_rustls(addr, tls_config)
            .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        tracing::warn!(
            cert_path = %config.security.web_tls_cert_path,
            key_path = %config.security.web_tls_key_path,
            "TLS certificates not found — falling back to plain HTTP."
        );
        tracing::info!(%addr, "fw-web listening (HTTP — no TLS)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}