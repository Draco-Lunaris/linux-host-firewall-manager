//! Secret key management for the web process.

use fw_core::crypto;

pub fn load_or_create_secret_key() -> Result<[u8; 32], fw_core::AppError> {
    crypto::load_or_create_key(fw_core::crypto::SECRET_ENCRYPTION_KEY_PATH)
}
