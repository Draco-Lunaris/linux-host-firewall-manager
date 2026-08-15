//! Drift history — the audit log of firewall-rule drift events.
//!
//! `drift_snapshots` records every check-in mismatch (the agent's live rules
//! differed from its assigned policy — `source = 'check_in_mismatch'`) and
//! every apply the agent reports back (`source = 'agent_report'`). Together
//! they form a long-running history an operator can use to investigate
//! unauthorized or out-of-band firewall changes. Rows are never purged, so the
//! table grows as a permanent audit trail; the list endpoint is capped with a
//! `limit` (default 200, max 1000) to keep the page responsive.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use fw_auth::rbac::AuthUser;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new().route("/snapshots", get(list_drift_snapshots))
}

#[derive(Debug, Deserialize, Default)]
pub struct DriftSnapshotQuery {
    pub host_id: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct DriftSnapshotRow {
    pub id: Uuid,
    pub host_id: Uuid,
    pub fqdn: String,
    pub display_name: String,
    pub snapshot_hash: String,
    pub rule_count: i32,
    pub source: String,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /api/v1/drift/snapshots[?host_id=&limit=]` — drift history across the
/// fleet, newest first. `check_in_mismatch` rows are drift events (live rules
/// diverged from policy); `agent_report` rows are the agent's applies (often
/// the correction following a mismatch). Optional `host_id` filters to one
/// host.
async fn list_drift_snapshots(
    State(state): State<std::sync::Arc<AppState>>,
    _auth: AuthUser,
    Query(q): Query<DriftSnapshotQuery>,
) -> Result<Json<Vec<DriftSnapshotRow>>, fw_core::AppError> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows: Vec<DriftSnapshotRow> = sqlx::query_as(
        "SELECT d.id, d.host_id, h.fqdn, h.display_name, d.snapshot_hash,
                d.rule_count, d.source, d.captured_at
         FROM drift_snapshots d
         JOIN hosts h ON h.id = d.host_id
         WHERE ($1::uuid IS NULL OR d.host_id = $1)
         ORDER BY d.captured_at DESC, d.id DESC
         LIMIT $2",
    )
    .bind(q.host_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}
