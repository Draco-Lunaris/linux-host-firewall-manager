use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentClientError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api error: {code} - {message}")]
    ApiError { code: String, message: String },
    #[error("not connected")]
    NotConnected,
    #[error("timeout")]
    Timeout,
}
