use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unprocessable entity: {0}")]
    UnprocessableEntity(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("config error: {0}")]
    Config(String),
}

pub type ApiResult<T> = Result<T, AppError>;

#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            AppError::NotFound(_) => (axum::http::StatusCode::NOT_FOUND, "not_found"),
            AppError::Unauthorized(_) => (axum::http::StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (axum::http::StatusCode::FORBIDDEN, "forbidden"),
            AppError::BadRequest(_) => (axum::http::StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Conflict(_) => (axum::http::StatusCode::CONFLICT, "conflict"),
            AppError::UnprocessableEntity(_) => (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "unprocessable_entity",
            ),
            AppError::Database(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
            ),
            AppError::Internal(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
            AppError::Config(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "config_error",
            ),
        };
        let body = ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: self.to_string(),
                request_id: None,
            },
        };
        (status, axum::Json(body)).into_response()
    }
}
