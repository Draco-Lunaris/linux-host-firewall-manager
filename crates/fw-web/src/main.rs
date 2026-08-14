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

    // Initialize CA (generates + persists the root CA on first run)
    let ca = std::sync::Arc::new(
        fw_ca::CertAuthority::init("/etc/firewall-manager/ca".to_string(), &db).await?,
    );

    // Capture server config before the AppConfig is moved into state.
    let agent_host = config.server.host.clone();
    let agent_port = config.server.agent_port;
    let agent_tls_cert_path = config.security.web_tls_cert_path.clone();
    let agent_tls_key_path = config.security.web_tls_key_path.clone();

    let state = fw_web::AppState {
        db,
        config: std::sync::Arc::new(config.clone()),
        signing_key_pem,
        auth_config,
        ws_tickets: std::sync::Arc::new(dashmap::DashMap::new()),
        ca: ca.clone(),
        approved_enrollments: std::sync::Arc::new(dashmap::DashMap::new()),
    };

    // ── Agent mTLS listener (SEC-008) ────────────────────────────────────
    // Serves only the agent API on a dedicated port with mandatory client-cert
    // verification pinned to the manager CA. Reuses the manager's web TLS
    // cert/key as the server identity. Requires TLS certs to be present.
    let tls_cert = std::path::Path::new(&agent_tls_cert_path);
    let tls_key = std::path::Path::new(&agent_tls_key_path);
    if tls_cert.exists() && tls_key.exists() {
        let server_cert_pem = std::fs::read_to_string(&agent_tls_cert_path)?;
        let server_key_pem = std::fs::read_to_string(&agent_tls_key_path)?;
        let agent_server_config = fw_web::agent_listener::build_agent_server_config(
            ca.root_cert_pem(),
            &server_cert_pem,
            &server_key_pem,
        )?;
        let agent_addr: std::net::SocketAddr = format!("{}:{}", agent_host, agent_port)
            .parse()
            .expect("Invalid agent bind address");
        let agent_listener =
            fw_web::agent_listener::AgentTlsListener::new(agent_addr, agent_server_config).await?;
        // Nest under /api/v1/agent so the routes match the agent client's URL
        // construction ({manager_url}/api/v1/agent/check-in) and the URL handed to
        // the agent at enrollment. The dedicated mTLS listener still owns these
        // routes; the prefix is path-only and does not affect ConnectInfo/HostIdentity.
        let agent_router = axum::Router::new()
            .nest("/api/v1/agent", fw_web::routes::agent_api::router())
            .with_state(std::sync::Arc::new(state.clone()));
        tracing::info!(%agent_addr, "agent mTLS API listening (mandatory client cert)");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                agent_listener,
                agent_router.into_make_service_with_connect_info::<fw_web::mtls::ClientCertInfo>(),
            )
            .await
            {
                tracing::error!(error = %e, "agent mTLS listener exited");
            }
        });
    } else {
        tracing::warn!(
            "TLS certificates not found — agent mTLS API disabled. Provide web_tls_cert_path / web_tls_key_path to enable agent check-ins."
        );
    }

    // ── Human UI listener (JWT-protected API + SPA) ───────────────────────
    let router = fw_web::build_router(state);
    let addr: std::net::SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid bind address");

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
