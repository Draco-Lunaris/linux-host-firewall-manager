use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::AppState;

pub async fn health_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    Json(serde_json::json!({
        "service": "firewall-manager-web",
        "version": env!("CARGO_PKG_VERSION"),
        "status": if db_ok { "healthy" } else { "degraded" },
        "database": if db_ok { "ok" } else { "error" },
    }))
}
