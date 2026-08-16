//! Audit external anchor — daily export of chain head to external store (SEC-004).

use sqlx::PgPool;
use std::sync::Arc;

pub async fn run(db: Arc<PgPool>) {
    loop {
        if let Err(e) = anchor_chain(&db).await {
            tracing::error!(error = %e, "Audit anchor cycle failed");
        }
        // Run daily
        tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
    }
}

async fn anchor_chain(db: &PgPool) -> Result<(), sqlx::Error> {
    // Get current chain head
    let chain_head: Option<String> =
        sqlx::query_scalar("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(db)
            .await?;

    if let Some(head) = chain_head {
        // In production: export to S3 Object Lock / RFC 3161 TSA / remote log host
        // For now, record the anchor locally
        sqlx::query(
            "INSERT INTO audit_anchor (chain_head, anchor_type, anchor_ref) VALUES ($1, 'remote_log_host', $2)",
        )
        .bind(&head)
        .bind(format!("local-anchor-{}", chrono::Utc::now().timestamp()))
        .execute(db)
        .await?;

        tracing::info!(chain_head = %head, "Audit chain anchored");

        // External verification (S3 Object Lock / RFC 3161 TSA / remote log host) is not
        // yet wired. Count unverified anchors and log a warning so the gap is visible — do
        // NOT mark them verified_ok. Real external anchoring is a documented follow-up.
        let unverified: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_anchor WHERE verified_at IS NULL")
                .fetch_one(db)
                .await
                .unwrap_or(0);

        if unverified > 0 {
            tracing::warn!(
                unverified,
                "Audit anchors await external verification (no external store configured)"
            );
        }
    }

    Ok(())
}
