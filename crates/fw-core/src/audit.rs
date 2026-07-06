use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityResult {
    pub verified: bool,
    pub mismatched_rows: Vec<i64>,
    pub total_rows: u64,
}

#[allow(clippy::too_many_arguments)]
pub async fn log_event(
    pool: &PgPool,
    action: &str,
    actor_user_id: Option<Uuid>,
    actor_username: Option<&str>,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: serde_json::Value,
    ip_address: Option<&str>,
    request_id: Option<&str>,
) {
    let now = chrono::Utc::now();
    let details_json = serde_json::to_string(&details).unwrap_or_default();

    let prev_hash: Option<String> =
        sqlx::query_scalar("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    let prev = prev_hash.unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(action.as_bytes());
    if let Some(uid) = actor_user_id {
        hasher.update(uid.to_string().as_bytes());
    }
    if let Some(u) = actor_username {
        hasher.update(u.as_bytes());
    }
    if let Some(tt) = target_type {
        hasher.update(tt.as_bytes());
    }
    if let Some(tid) = target_id {
        hasher.update(tid.as_bytes());
    }
    hasher.update(details_json.as_bytes());
    if let Some(ip) = ip_address {
        hasher.update(ip.as_bytes());
    }
    if let Some(rid) = request_id {
        hasher.update(rid.as_bytes());
    }
    hasher.update(now.to_rfc3339().as_bytes());
    let row_hash = hex::encode(hasher.finalize());

    let _ = sqlx::query(
        "INSERT INTO audit_log (action, actor_user_id, actor_username, target_type, target_id, details, ip_address, request_id, created_at, row_hash, prev_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(action)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(target_type)
    .bind(target_id)
    .bind(&details_json)
    .bind(ip_address)
    .bind(request_id)
    .bind(now)
    .bind(&row_hash)
    .bind(&prev)
    .execute(pool)
    .await;
}

pub async fn verify_integrity(pool: &PgPool) -> Result<IntegrityResult, crate::error::AppError> {
    let rows: Vec<(
        i64,
        String,
        String,
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
        serde_json::Value,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, action, row_hash, prev_hash, actor_user_id, actor_username, target_type, target_id, details, ip_address, request_id, created_at
         FROM audit_log ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| crate::error::AppError::Database(e))?;

    let mut mismatched = Vec::new();
    let mut prev = String::new();
    let total = rows.len() as u64;

    for row in &rows {
        let details_json = serde_json::to_string(&row.8).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(row.1.as_bytes());
        if let Some(uid) = row.4 {
            hasher.update(uid.to_string().as_bytes());
        }
        if let Some(u) = &row.5 {
            hasher.update(u.as_bytes());
        }
        if let Some(tt) = &row.6 {
            hasher.update(tt.as_bytes());
        }
        if let Some(tid) = &row.7 {
            hasher.update(tid.as_bytes());
        }
        hasher.update(details_json.as_bytes());
        if let Some(ip) = &row.9 {
            hasher.update(ip.as_bytes());
        }
        if let Some(rid) = &row.10 {
            hasher.update(rid.as_bytes());
        }
        hasher.update(row.11.to_rfc3339().as_bytes());
        let expected = hex::encode(hasher.finalize());
        if expected != row.2 {
            mismatched.push(row.0);
        }
        prev = row.2.clone();
    }

    Ok(IntegrityResult {
        verified: mismatched.is_empty(),
        mismatched_rows: mismatched,
        total_rows: total,
    })
}
