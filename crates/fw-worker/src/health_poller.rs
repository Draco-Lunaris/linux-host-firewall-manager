//! Health poller — polls agent /health endpoints every 5 minutes.

use sqlx::PgPool;
use std::sync::Arc;

pub async fn run(db: Arc<PgPool>) {
    loop {
        tracing::debug!("Health poll cycle starting");
        if let Err(e) = poll_health(&db).await {
            tracing::error!(error = %e, "Health poll cycle failed");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
    }
}

async fn poll_health(db: &PgPool) -> Result<(), sqlx::Error> {
    let hosts: Vec<(uuid::Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, fqdn, ip_address::text FROM hosts WHERE health_status != 'unreachable'",
    )
    .fetch_all(db)
    .await?;

    for (host_id, fqdn, ip) in hosts {
        // In production: call fw_agent_client::AgentClient::health()
        // Update hosts.health_status, etc.
        tracing::debug!(host = %host_id, fqdn = %fqdn, ip = ?ip, "Polling health");
    }

    Ok(())
}
