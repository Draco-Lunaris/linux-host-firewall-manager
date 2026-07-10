use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::server::AgentState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime: u64,
    pub version: String,
    pub backend_active: String,
    pub container_runtime: Option<String>,
    pub safe_mode: bool,
}

pub async fn health_handler(State(state): State<Arc<AgentState>>) -> Json<HealthResponse> {
    let container_runtime = crate::backend::container_detect::detect_container_runtime();
    let safe_mode = state.safe_mode.is_active();

    Json(HealthResponse {
        status: "ok".to_string(),
        uptime: 0,
        version: env!("CARGO_PKG_VERSION").to_string(),
        backend_active: state.backend_name.clone(),
        container_runtime,
        safe_mode,
    })
}