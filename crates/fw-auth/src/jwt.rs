use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_ACCESS_TTL_SECS: i64 = 900;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub role: String,
    pub username: String,
}

impl AccessClaims {
    pub fn user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("token expired")]
    Expired,
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("key load error: {0}")]
    KeyLoad(String),
}

pub fn issue_access_token(
    signing_key_pem: &str,
    user_id: Uuid,
    role: &str,
    username: &str,
) -> Result<(String, String), JwtError> {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();
    let claims = AccessClaims {
        sub: user_id.to_string(),
        iat: now,
        exp: now + DEFAULT_ACCESS_TTL_SECS,
        jti: jti.clone(),
        role: role.to_string(),
        username: username.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(signing_key_pem.as_bytes())
        .map_err(|e| JwtError::Encode(e.to_string()))?;
    let token = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| JwtError::Encode(e.to_string()))?;
    Ok((token, jti))
}

pub fn validate_access_token(verify_key_pem: &str, token: &str) -> Result<AccessClaims, JwtError> {
    let key = DecodingKey::from_rsa_pem(verify_key_pem.as_bytes())
        .map_err(|e| JwtError::Decode(e.to_string()))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 5;
    let data = decode::<AccessClaims>(token, &key, &validation).map_err(|e| {
        if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
            JwtError::Expired
        } else {
            JwtError::Decode(e.to_string())
        }
    })?;
    Ok(data.claims)
}

pub fn load_signing_key(path: &str) -> Result<String, JwtError> {
    std::fs::read_to_string(path).map_err(|e| JwtError::KeyLoad(e.to_string()))
}

pub fn load_verify_key(path: &str) -> Result<String, JwtError> {
    std::fs::read_to_string(path).map_err(|e| JwtError::KeyLoad(e.to_string()))
}

#[allow(dead_code)]
fn _unused() -> Duration {
    Duration::seconds(DEFAULT_ACCESS_TTL_SECS)
}
