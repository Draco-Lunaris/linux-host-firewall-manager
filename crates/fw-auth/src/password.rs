use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;

const M_COST: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

pub fn hash_password(password: &str) -> Result<String, crate::error::PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(M_COST, T_COST, P_COST, None)
            .map_err(|e| crate::error::PasswordError::Hash(e.to_string()))?,
    );
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| crate::error::PasswordError::Hash(e.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, crate::error::PasswordError> {
    let parsed =
        PasswordHash::new(hash).map_err(|e| crate::error::PasswordError::Verify(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn validate_password_strength(password: &str) -> Result<(), crate::error::PasswordError> {
    if password.len() < 8 {
        return Err(crate::error::PasswordError::Weak(
            "must be at least 8 characters".to_string(),
        ));
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(crate::error::PasswordError::Weak(
            "must contain an uppercase letter".to_string(),
        ));
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(crate::error::PasswordError::Weak(
            "must contain a lowercase letter".to_string(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(crate::error::PasswordError::Weak(
            "must contain a digit".to_string(),
        ));
    }
    if !password
        .chars()
        .any(|c| !c.is_alphanumeric() && c.is_ascii())
    {
        return Err(crate::error::PasswordError::Weak(
            "must contain a special character".to_string(),
        ));
    }
    Ok(())
}
