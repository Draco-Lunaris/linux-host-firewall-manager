//! Deployment endpoint — deploy a policy set to hosts (creates FirewallJob).

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use fw_auth::rbac::AuthUser;
use fw_core::models::FirewallJob;
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new().route("/", post(deploy_policy_set))
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub policy_set_id: Uuid,
    pub host_ids: Vec<Uuid>,
    pub immediate: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
pub struct DeployResponse {
    pub job_id: Uuid,
    pub host_count: usize,
    pub status: String,
}

async fn deploy_policy_set(
    State(state): State<std::sync::Arc<AppState>>,
    auth: AuthUser,
    Json(req): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeployResponse>), fw_core::AppError> {
    if !auth.role.can_write() {
        return Err(fw_core::AppError::Forbidden(
            "Write access required".to_string(),
        ));
    }

    let immediate = req.immediate.unwrap_or(true);
    let host_count = req.host_ids.len();

    // Create the job
    let job: FirewallJob = sqlx::query_as(
        "INSERT INTO firewall_jobs (kind, status, created_by_user_id, immediate, policy_set_id)
         VALUES ('rule_apply', 'queued', $1, $2, $3) RETURNING *",
    )
    .bind(auth.user_id)
    .bind(immediate)
    .bind(req.policy_set_id)
    .fetch_one(&state.db)
    .await?;

    // Create per-host entries
    for host_id in &req.host_ids {
        // Check operator scoping (SEC-012)
        let can_access = fw_auth::can_access_host(&state.db, &auth, *host_id)
            .await
            .unwrap_or(false);
        if !can_access {
            return Err(fw_core::AppError::Forbidden(format!(
                "Operator {} cannot access host {}",
                auth.username, host_id
            )));
        }

        sqlx::query(
            "INSERT INTO firewall_job_hosts (job_id, host_id, status) VALUES ($1, $2, 'queued')",
        )
        .bind(job.id)
        .bind(host_id)
        .execute(&state.db)
        .await?;
    }

    // NOTIFY the worker
    let _ = sqlx::query("SELECT pg_notify('job_enqueued', $1)")
        .bind(job.id.to_string())
        .execute(&state.db)
        .await;

    // Audit log
    let _ = fw_core::audit::log_event(
        &state.db,
        "firewall_job_created",
        Some(auth.user_id),
        Some(&auth.username),
        Some("job"),
        Some(&job.id.to_string()),
        serde_json::json!({
            "policy_set_id": req.policy_set_id,
            "host_count": host_count,
            "immediate": immediate
        }),
        auth.ip.map(|ip| ip.to_string()).as_deref(),
        None,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(DeployResponse {
            job_id: job.id,
            host_count,
            status: "queued".to_string(),
        }),
    ))
}
