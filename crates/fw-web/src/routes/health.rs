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

pub async fn fleet_status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let total_hosts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let healthy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'healthy'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let degraded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'degraded'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let unreachable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'unreachable'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'pending'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rules")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_jobs")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let pending_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_jobs WHERE status IN ('queued', 'pending', 'running')")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    Json(serde_json::json!({
        "total_hosts": total_hosts,
        "healthy": healthy,
        "degraded": degraded,
        "unreachable": unreachable,
        "pending": pending,
        "total_rules": total_rules,
        "total_jobs": total_jobs,
        "pending_jobs": pending_jobs,
        "compliance_pct": if total_hosts > 0 { 100.0 } else { 0.0 },
        "total_pending_patches": 0,
        "hosts_requiring_reboot": 0,
    }))
}