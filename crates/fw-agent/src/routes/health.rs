use axum::extract::State;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime: u64,
    pub version: String,
    pub crl_status: String,
    pub gpg_key_status: String,
    pub backend_active: String,
    pub container_runtime: Option<String>,
}

pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        uptime: 0,
        version: env!("CARGO_PKG_VERSION").to_string(),
        crl_status: "valid".into(),
        gpg_key_status: "valid".into(),
        backend_active: "ufw".into(),
        container_runtime: None,
    })
}
