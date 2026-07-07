//! Agent HTTPS server with mTLS.

use crate::backend::{self, FirewallBackend};
use crate::config::AgentConfig;
use crate::mtls;
use crate::protected_cidrs;
use crate::routes;
use crate::safe_mode::SafeModeState;
use anyhow::{Context, Result};
use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::sync::Arc;

pub async fn run() -> Result<()> {
    let config =
        AgentConfig::load().context("No agent config found — run `fw-agent enroll` first")?;

    // Load mTLS certs
    let certs = mtls::load_certs(&config.cert_dir).context("Failed to load mTLS certificates")?;

    // Detect firewall backend
    let backend = backend::detect();
    let backend_name = backend
        .as_ref()
        .map(|b| b.name())
        .unwrap_or("none")
        .to_string();
    tracing::info!("Firewall backend: {}", backend_name);

    // Check container runtime (SEC-005)
    if let Some(runtime) = crate::backend::container_detect::detect_container_runtime() {
        tracing::warn!(
            runtime = %runtime,
            "Container runtime detected — UFW backend may conflict with container networking"
        );
    }

    // Initialize safe mode state
    let safe_mode = Arc::new(SafeModeState::new(config.safe_mode_timeout_secs));

    // Build TLS config with mTLS client verification
    let mut root_store = RootCertStore::empty();
    root_store
        .add(certs.ca_cert.clone())
        .context("Failed to add CA cert to root store")?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("Failed to build client verifier")?;

    let tls_config = RustlsConfig::from_der(
        certs
            .cert_chain
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect(),
        certs.private_key.secret_der().to_vec(),
    )
    .await
    .context("Failed to build TLS config")?;

    // Build router
    let state = Arc::new(AgentState {
        config: config.clone(),
        backend,
        safe_mode,
        backend_name,
    });

    let app = Router::new()
        .route("/api/v1/health", get(routes::health::health_handler))
        .route(
            "/api/v1/system/info",
            get(routes::system_info::system_info_handler),
        )
        .route(
            "/api/v1/rules/snapshot",
            get(routes::rules::snapshot_handler),
        )
        .route(
            "/api/v1/rules/apply",
            axum::routing::post(routes::rules::apply_handler),
        )
        .route(
            "/api/v1/rules/reset",
            axum::routing::post(routes::rules::reset_handler),
        )
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.listen_port);
    tracing::info!("fw-agent listening on {}", addr);

    axum_server::bind_rustls(addr.parse().unwrap(), tls_config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .context("Server error")?;

    Ok(())
}

pub struct AgentState {
    pub config: AgentConfig,
    pub backend: Option<Box<dyn FirewallBackend>>,
    pub safe_mode: Arc<SafeModeState>,
    pub backend_name: String,
}
