use sqlx::PgPool;

pub async fn generate_csv(
    _pool: &PgPool,
    _report_type: &str,
) -> Result<Vec<u8>, crate::error::ReportError> {
    Ok(Vec::new())
}
