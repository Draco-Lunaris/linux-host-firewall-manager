//! Refresh listener — LISTEN for NOTIFY events from PostgreSQL.

use sqlx::PgPool;
use std::sync::Arc;

pub async fn run(db: Arc<PgPool>) {
    // In production: use sqlx::postgres::PgListener to listen for:
    // - job_enqueued: wake job executor
    // - refresh_requested: reload config
    // - discovery_enqueued: trigger discovery scan
    // For now, just log
    tracing::info!("Refresh listener started (stub)");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
