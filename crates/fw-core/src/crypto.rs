use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use std::path::Path;

pub const KEY_PATH: &str = "/etc/firewall-manager/keys/health-check.key";
pub const SECRET_ENCRYPTION_KEY_PATH: &str = "/etc/firewall-manager/keys/secret-encryption.key";

pub fn load_or_create_key(path: &str) -> Result<[u8; 32], crate::error::AppError> {
    if Path::new(path).exists() {
        let data = std::fs::read(path)
            .map_err(|e| crate::error::AppError::Internal(format!("read key {}: {}", path, e)))?;
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            Ok(key)
        } else {
            Err(crate::error::AppError::Internal(format!(
                "key {} is not 32 bytes",
                path
            )))
        }
    } else {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::error::AppError::Internal(format!("mkdir {}: {}", parent.display(), e))
            })?;
        }
        std::fs::write(path, key)
            .map_err(|e| crate::error::AppError::Internal(format!("write key {}: {}", path, e)))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| crate::error::AppError::Internal(format!("chmod {}: {}", path, e)))?;
        Ok(key)
    }
}

pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), crate::error::AppError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| crate::error::AppError::Internal(format!("encrypt: {}", e)))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, crate::error::AppError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::error::AppError::Internal(format!("decrypt: {}", e)))
}
