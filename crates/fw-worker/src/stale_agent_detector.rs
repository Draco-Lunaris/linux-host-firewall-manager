//! Stale agent detector — marks hosts as degraded/unreachable based on check-in staleness.
//!
//! Replaces the old health_poller. Instead of actively polling agents, this module
//! checks the last check-in time for each host and updates health_status accordingly:
//! - healthy: checked in within 2x configured interval
//! - degraded: checked in within 4x configured interval
//! - unreachable: hasn't checked in within 4x configured interval

use sqlx::PgPool;
use std::sync::Arc;

pub async fn run(db: Arc<PgPool>) {
    loop {
        tracing::debug!("Stale agent detection cycle starting");
        if let Err(e) = detect_stale_agents(&db).await {
            tracing::error!(error = %e, "Stale agent detection failed");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
    }
}

async fn detect_stale_agents(db: &PgPool) -> Result<(), sqlx::Error> {
    // Get all hosts with their last check-in time and configured interval
    let hosts: Vec<(uuid::Uuid, String, Option<chrono::DateTime<chrono::Utc>>, Option<i32>)> =
        sqlx::query_as(
            "SELECT h.id, h.fqdn, MAX(ac.checked_in_at) as last_check_in, hco.check_in_interval_secs
             FROM hosts h
             LEFT JOIN agent_check_ins ac ON ac.host_id = h.id
             LEFT JOIN host_config_overrides hco ON hco.host_id = h.id
             WHERE h.health_status != 'unreachable' OR h.last_health_at IS NULL
             GROUP BY h.id, h.fqdn, hco.check_in_interval_secs",
        )
        .fetch_all(db)
        .await?;

    let now = chrono::Utc::now();

    for (host_id, fqdn, last_check_in, interval_secs) in hosts {
        let interval = interval_secs.unwrap_or(900) as i64;
        let stale_2x = interval * 2;
        let stale_4x = interval * 4;

        let new_status = match last_check_in {
            Some(last) => {
                let elapsed = (now - last).num_seconds();
                if elapsed > stale_4x {
                    "unreachable"
                } else if elapsed > stale_2x {
                    "degraded"
                } else {
                    "healthy"
                }
            }
            None => {
                // Never checked in — if host was just enrolled, give it a grace period
                // For now, mark as pending (will be updated on first check-in)
                "pending"
            }
        };

        // Update host health status
        let _ = sqlx::query("UPDATE hosts SET health_status = $2::host_health_status WHERE id = $1 AND health_status != $2::host_health_status")
            .bind(host_id)
            .bind(new_status)
            .execute(db)
            .await;

        tracing::debug!(
            host = %host_id,
            fqdn = %fqdn,
            status = new_status,
            last_check_in = ?last_check_in,
            "Host health updated"
        );
    }

    Ok(())
}