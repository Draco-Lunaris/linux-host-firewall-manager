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

    let healthy: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'healthy'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let degraded: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'degraded'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let unreachable: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'unreachable'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE health_status = 'pending'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let total_rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rules")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let policy_sets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_policy_sets")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    // Hosts currently in drift: whose most recent drift_snapshot is a
    // check-in mismatch (drifted) with no subsequent agent_report (apply /
    // correction) after it. Unlike a rolling 24h "ever drifted" count, this
    // drops to 0 the moment an agent self-corrects — it reflects current
    // state, not history. The full drift history lives in `drift_snapshots`
    // (surfaced via GET /api/v1/drift/snapshots) for investigating
    // unauthorized changes.
    let hosts_in_drift: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ( \
            SELECT DISTINCT ON (host_id) host_id, source \
            FROM drift_snapshots ORDER BY host_id, captured_at DESC, id DESC \
         ) latest WHERE latest.source = 'check_in_mismatch'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    // Pull-model liveness: check-ins received in the last 15 minutes (default
    // check-in interval). Zero means no agent has checked in recently.
    let recent_check_ins: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_check_ins \
         WHERE checked_in_at > NOW() - INTERVAL '15 minutes'",
    )
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
        "policy_sets": policy_sets,
        "hosts_in_drift": hosts_in_drift,
        "recent_check_ins": recent_check_ins,
    }))
}
