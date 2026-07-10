//! fw-worker — background worker for Linux Host Firewall Manager.
//!
//! Responsibilities (hybrid push/pull model):
//! - Stale agent detection (5-min) — marks hosts degraded/unreachable based on check-in staleness
//! - Push dispatcher — attempts emergency push of high-priority pending actions
//! - Audit integrity verification (daily)
//! - Audit external anchoring (daily — SEC-004)
//! - Refresh listener (PostgreSQL NOTIFY events)

use fw_core::AppConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;

mod audit_anchor;
mod push_dispatcher;
mod refresh_listener;
mod stale_agent_detector;

const REQUIRED_MIGRATION_COUNT: i32 = 29;
const SCHEMA_CHECK_TIMEOUT_SECS: u64 = 120;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_worker=debug,fw_core=debug,info".into()),
        )
        .init();

    let config = AppConfig::load()?;
    let db = fw_core::db::init_pool(&config.database.url).await?;

    // Wait for migrations
    wait_for_migrations(&db).await;
    tracing::info!("fw-worker starting (migrations verified)");

    let semaphore = Arc::new(Semaphore::new(config.worker.max_concurrent_agent_calls));
    let db = Arc::new(db);

    // Spawn background tasks
    let db1 = db.clone();
    tokio::spawn(async move { stale_agent_detector::run(db1).await });

    let db2 = db.clone();
    tokio::spawn(async move { audit_anchor::run(db2).await });

    let db3 = db.clone();
    tokio::spawn(async move { refresh_listener::run(db3).await });

    // Main loop: push dispatcher (emergency push only)
    let db4 = db.clone();
    let sem = semaphore.clone();
    tokio::spawn(async move { push_dispatcher::run(db4, sem).await });

    // Heartbeat
    let db5 = db.clone();
    tokio::spawn(async move {
        loop {
            let _ = sqlx::query("INSERT INTO worker_heartbeat (id, last_seen, worker_version) VALUES (1, NOW(), $1) ON CONFLICT (id) DO UPDATE SET last_seen = NOW(), worker_version = $1")
                .bind(env!("CARGO_PKG_VERSION"))
                .execute(&*db5)
                .await;
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        }
    });

    // Keep running
    tokio::signal::ctrl_c().await?;
    tracing::info!("fw-worker shutting down");
    Ok(())
}

async fn wait_for_migrations(db: &PgPool) {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(SCHEMA_CHECK_TIMEOUT_SECS);
    loop {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(db)
            .await
            .unwrap_or(0);
        if count >= REQUIRED_MIGRATION_COUNT as i64 {
            tracing::info!(migrations = count, "Schema version OK");
            return;
        }
        if tokio::time::Instant::now() > deadline {
            tracing::error!(
                current = count,
                required = REQUIRED_MIGRATION_COUNT,
                "Schema version timeout"
            );
            std::process::exit(1);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}