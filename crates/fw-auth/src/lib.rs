pub mod error;
pub mod jwt;
pub mod password;
pub mod rbac;
pub mod session;

pub use error::{JwtError, PasswordError, SessionError};
pub use jwt::{issue_access_token, validate_access_token, AccessClaims};
pub use password::{hash_password, validate_password_strength, verify_password};
pub use rbac::{
    can_access_host, is_jti_revoked, require_admin, require_auth, AuthConfig, AuthUser, UserRole,
};

// Error conversions into fw_core::AppError (fw-auth depends on fw-core)
impl From<JwtError> for fw_core::AppError {
    fn from(e: JwtError) -> Self {
        fw_core::AppError::Internal(format!("JWT error: {}", e))
    }
}

impl From<PasswordError> for fw_core::AppError {
    fn from(e: PasswordError) -> Self {
        match e {
            PasswordError::Weak(msg) => {
                fw_core::AppError::BadRequest(format!("Weak password: {}", msg))
            }
            other => fw_core::AppError::Internal(format!("Password error: {}", other)),
        }
    }
}
