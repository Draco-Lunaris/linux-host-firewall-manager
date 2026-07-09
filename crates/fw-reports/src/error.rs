use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid report type: {0}")]
    InvalidType(String),
}
