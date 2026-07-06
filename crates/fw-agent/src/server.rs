use crate::routes;
use axum::routing::{get, post};
use axum::Router;

pub async fn run() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/v1/health", get(routes::health::health_handler))
        .route(
            "/api/v1/rules/snapshot",
            get(routes::rules::snapshot_handler),
        )
        .route("/api/v1/rules/apply", post(routes::rules::apply_handler))
        .route("/api/v1/rules/reset", post(routes::rules::reset_handler));

    let port = 12443;
    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("fw-agent listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
