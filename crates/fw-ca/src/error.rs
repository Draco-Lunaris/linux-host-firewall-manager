use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("not implemented")]
    NotImplemented,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen error: {0}")]
    Rcgen(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}
