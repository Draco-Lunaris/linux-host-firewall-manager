//! Job executor — picks up queued jobs, acquires per-host lock, deploys to agents.

use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn run(db: Arc<PgPool>, semaphore: Arc<Semaphore>) {
    loop {
        // Try to acquire a job
        let job: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM firewall_jobs WHERE status = 'queued' AND immediate = TRUE
             ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&*db)
        .await
        .ok()
        .flatten();

        if let Some(job_id) = job {
            let db = db.clone();
            let _permit = semaphore.acquire().await;
            tokio::spawn(async move {
                if let Err(e) = execute_job(&db, job_id).await {
                    tracing::error!(job = %job_id, error = %e, "Job execution failed");
                }
            });
        } else {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

async fn execute_job(db: &PgPool, job_id: uuid::Uuid) -> Result<(), sqlx::Error> {
    // Mark job as running
    sqlx::query("UPDATE firewall_jobs SET status = 'running', started_at = NOW() WHERE id = $1")
        .bind(job_id)
        .execute(db)
        .await?;

    // Get hosts for this job
    let hosts: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        "SELECT id, host_id FROM firewall_job_hosts WHERE job_id = $1 AND status = 'queued'",
    )
    .bind(job_id)
    .fetch_all(db)
    .await?;

    for (jh_id, host_id) in hosts {
        // Acquire per-host lock (SEC-013)
        let lock_result = sqlx::query(
            "INSERT INTO host_apply_locks (host_id, locked_by_job) VALUES ($1, $2) ON CONFLICT (host_id) DO NOTHING",
        )
        .bind(host_id)
        .bind(job_id)
        .execute(db)
        .await?;

        if lock_result.rows_affected() == 0 {
            // Host is locked by another job — skip for now
            tracing::info!(host = %host_id, "Host locked, skipping");
            continue;
        }

        // Deploy rules to agent (stub — will call fw-agent-client)
        // For now, mark as succeeded
        sqlx::query(
            "UPDATE firewall_job_hosts SET status = 'succeeded', completed_at = NOW() WHERE id = $1",
        )
        .bind(jh_id)
        .execute(db)
        .await?;

        // Release lock
        sqlx::query("DELETE FROM host_apply_locks WHERE host_id = $1")
            .bind(host_id)
            .execute(db)
            .await?;
    }

    // Mark job as completed
    sqlx::query(
        "UPDATE firewall_jobs SET status = 'succeeded', completed_at = NOW() WHERE id = $1",
    )
    .bind(job_id)
    .execute(db)
    .await?;

    // Audit log
    let _ = fw_core::audit::log_event(
        db,
        "firewall_job_completed",
        None,
        None,
        Some("job"),
        Some(&job_id.to_string()),
        serde_json::json!({}),
        None,
        None,
    )
    .await;

    Ok(())
}
