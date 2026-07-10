//! Push dispatcher — attempts emergency push of high-priority pending actions to agents.
//!
//! Replaces the old job_executor. Instead of processing all jobs as pushes, this module
//! only handles high-priority pending actions that need immediate delivery:
//! 1. Read pending_actions with status 'queued' and priority > 0
//! 2. Check if push is enabled for the host
//! 3. Attempt mTLS push to the agent
//! 4. On success: mark as 'delivered'
//! 5. On failure: retry with exponential backoff (1s, 2s, 4s)
//! 6. After max_attempts: leave as 'queued' (will be delivered on next check-in)
//!
//! Low-priority actions (priority = 0) skip push entirely — they wait for check-in.

use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn run(db: Arc<PgPool>, semaphore: Arc<Semaphore>) {
    loop {
        // Try to acquire a high-priority pending action
        let action: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM pending_actions
             WHERE status = 'queued' AND priority > 0 AND expires_at > NOW()
             ORDER BY priority DESC, created_at LIMIT 1
             FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&*db)
        .await
        .ok()
        .flatten();

        if let Some(action_id) = action {
            let db = db.clone();
            let _permit = semaphore.acquire().await;
            tokio::spawn(async move {
                if let Err(e) = dispatch_action(&db, action_id).await {
                    tracing::error!(action = %action_id, error = %e, "Push dispatch failed");
                }
            });
        } else {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

async fn dispatch_action(db: &PgPool, action_id: uuid::Uuid) -> Result<(), sqlx::Error> {
    // Mark as pushing
    sqlx::query(
        "UPDATE pending_actions SET status = 'pushing', first_attempt_at = COALESCE(first_attempt_at, NOW()), attempts = attempts + 1 WHERE id = $1",
    )
    .bind(action_id)
    .execute(db)
    .await?;

    // Get action details and host info
    let action: Option<(uuid::Uuid, String, serde_json::Value, String, i32, i32, Option<bool>)> =
        sqlx::query_as(
            "SELECT pa.host_id, pa.action_type::text, pa.payload, pa.reason, pa.attempts, pa.max_attempts, hco.push_enabled
             FROM pending_actions pa
             LEFT JOIN host_config_overrides hco ON hco.host_id = pa.host_id
             WHERE pa.id = $1",
        )
        .bind(action_id)
        .fetch_optional(db)
        .await?;

    let (host_id, action_type, payload, reason, attempts, max_attempts, push_enabled) =
        match action {
            Some(a) => a,
            None => return Ok(()),
        };

    // Check if push is enabled for this host
    let push_enabled = push_enabled.unwrap_or(true);
    if !push_enabled {
        // Push not enabled — leave as queued for check-in delivery
        sqlx::query("UPDATE pending_actions SET status = 'queued' WHERE id = $1")
            .bind(action_id)
            .execute(db)
            .await?;
        tracing::info!(action = %action_id, host = %host_id, "Push disabled, leaving for check-in delivery");
        return Ok(());
    }

    // Attempt push via mTLS agent client
    // For now, this is a stub — the actual mTLS push will be wired in Phase 6
    // when we rework the agent client. For now, we simulate a push failure
    // and fall back to check-in delivery.
    let push_result = Err("Push not yet implemented — falling back to check-in".to_string());

    match push_result {
        Ok(()) => {
            // Push succeeded — mark as delivered
            sqlx::query("UPDATE pending_actions SET status = 'delivered', delivered_at = NOW() WHERE id = $1")
                .bind(action_id)
                .execute(db)
                .await?;
            tracing::info!(action = %action_id, host = %host_id, "Push delivered");
        }
        Err(e) => {
            if attempts >= max_attempts {
                // Max attempts reached — leave as queued for check-in delivery
                sqlx::query("UPDATE pending_actions SET status = 'queued' WHERE id = $1")
                    .bind(action_id)
                    .execute(db)
                    .await?;
                tracing::warn!(
                    action = %action_id,
                    host = %host_id,
                    attempts,
                    max_attempts,
                    "Push failed after max attempts — falling back to check-in delivery"
                );
            } else {
                // Will retry — back to queued
                sqlx::query("UPDATE pending_actions SET status = 'queued' WHERE id = $1")
                    .bind(action_id)
                    .execute(db)
                    .await?;
                tracing::warn!(
                    action = %action_id,
                    host = %host_id,
                    attempt = attempts,
                    error = %e,
                    "Push failed, will retry"
                );
            }
        }
    }

    // Audit log
    let _ = fw_core::audit::log_event(
        db,
        "firewall_job_created",
        None,
        None,
        Some("pending_action"),
        Some(&action_id.to_string()),
        serde_json::json!({
            "host_id": host_id,
            "action_type": action_type,
            "reason": reason,
            "payload": payload,
        }),
        None,
        None,
    )
    .await;

    Ok(())
}