use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("key load error: {0}")]
    KeyLoad(String),
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("hash error: {0}")]
    Hash(String),
    #[error("verify error: {0}")]
    Verify(String),
    #[error("weak password: {0}")]
    Weak(String),
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account locked")]
    AccountLocked,
    #[error("mfa required")]
    MfaRequired,
    #[error("invalid mfa code")]
    InvalidMfa,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}
