//! Drift poller — fetches rule snapshots from agents, detects drift (SEC-006).

use sqlx::PgPool;
use std::sync::Arc;

pub async fn run(db: Arc<PgPool>, interval_secs: u64) {
    loop {
        tracing::debug!("Drift poll cycle starting");
        if let Err(e) = poll_drift(&db).await {
            tracing::error!(error = %e, "Drift poll cycle failed");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}

async fn poll_drift(db: &PgPool) -> Result<(), sqlx::Error> {
    // Get all active hosts
    let hosts: Vec<(uuid::Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, fqdn, ip_address::text FROM hosts WHERE health_status IN ('healthy', 'degraded')",
    )
    .fetch_all(db)
    .await?;

    for (host_id, fqdn, ip) in hosts {
        // In production: call fw_agent_client::AgentClient::get_snapshot()
        // For now, stub — just log
        tracing::debug!(host = %host_id, fqdn = %fqdn, "Checking drift for host");

        // Compare current snapshot hash to last recorded
        let last_hash: Option<String> = sqlx::query_scalar(
            "SELECT snapshot_hash FROM drift_snapshots WHERE host_id = $1 ORDER BY captured_at DESC LIMIT 1",
        )
        .bind(host_id)
        .fetch_optional(db)
        .await?;

        // If we had a snapshot from the agent, compare
        // For now, this is a no-op until agent client is wired
        let _ = last_hash;
    }

    Ok(())
}
