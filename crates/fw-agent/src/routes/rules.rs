use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ApplyRequest {
    pub rules: Vec<serde_json::Value>,
    pub job_id: String,
}

#[derive(Serialize)]
pub struct ApplyResponse {
    pub job_id: String,
    pub applied: u32,
    pub failed: u32,
    pub snapshot_hash: String,
    pub error: Option<String>,
}

pub async fn apply_handler(Json(req): Json<ApplyRequest>) -> Json<ApplyResponse> {
    Json(ApplyResponse {
        job_id: req.job_id,
        applied: 0,
        failed: 0,
        snapshot_hash: String::new(),
        error: None,
    })
}

pub async fn snapshot_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": [],
        "snapshot_hash": "",
        "rule_count": 0,
    }))
}

pub async fn reset_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}
