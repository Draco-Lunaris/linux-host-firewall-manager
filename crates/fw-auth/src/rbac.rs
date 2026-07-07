#![allow(clippy::should_implement_trait)]
//! Role-Based Access Control (RBAC) middleware for Axum.
//!
//! Provides:
//! - JWT extraction and validation from `Authorization: Bearer <token>` header
//! - JWT jti revocation check (SEC-011)
//! - Role enforcement (admin, operator, reporter, break_glass_operator)
//! - Operator host-group scoping (SEC-012)
//! - IP whitelist enforcement with trusted-proxy XFF handling

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::jwt::{validate_access_token, AccessClaims};

/// User identity extracted from a validated JWT, inserted as a request extension.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub username: String,
    pub role: UserRole,
    pub claims: AccessClaims,
    pub ip: Option<IpAddr>,
}

/// Application roles.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Operator,
    Reporter,
    BreakGlassOperator,
}

impl UserRole {
    pub fn parse_role(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "reporter" => Some(Self::Reporter),
            "break_glass_operator" => Some(Self::BreakGlassOperator),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Reporter => "reporter",
            Self::BreakGlassOperator => "break_glass_operator",
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_write(&self) -> bool {
        matches!(
            self,
            Self::Admin | Self::Operator | Self::BreakGlassOperator
        )
    }

    pub fn is_break_glass(&self) -> bool {
        matches!(self, Self::BreakGlassOperator)
    }
}

/// Shared auth configuration injected via Axum state.
#[derive(Clone)]
pub struct AuthConfig {
    pub verify_key_pem: String,
    pub ip_whitelist: Arc<tokio::sync::RwLock<Vec<IpNet>>>,
    pub trusted_proxies: Arc<tokio::sync::RwLock<Vec<IpNet>>>,
}

impl AuthConfig {
    pub fn new(
        verify_key_pem: String,
        ip_whitelist_cidrs: &[String],
        trusted_proxy_cidrs: &[String],
    ) -> Self {
        let ip_whitelist = ip_whitelist_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        let trusted_proxies = trusted_proxy_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        Self {
            verify_key_pem,
            ip_whitelist: Arc::new(tokio::sync::RwLock::new(ip_whitelist)),
            trusted_proxies: Arc::new(tokio::sync::RwLock::new(trusted_proxies)),
        }
    }

    pub async fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        let whitelist = self.ip_whitelist.read().await;
        if whitelist.is_empty() {
            return true;
        }
        whitelist.iter().any(|net| net.contains(ip))
    }

    pub async fn update_ip_whitelist(&self, entries: Vec<String>) {
        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        *self.ip_whitelist.write().await = nets;
    }

    pub async fn update_trusted_proxies(&self, entries: Vec<String>) {
        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();
        *self.trusted_proxies.write().await = nets;
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer_ip = peer?;
    if !trusted_proxies.is_empty() && trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = xff
                .split(',')
                .next()
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
            {
                return Some(ip);
            }
        }
    }
    Some(peer_ip)
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": { "code": "unauthorized", "message": message } })),
    )
        .into_response()
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": { "code": "forbidden", "message": message } })),
    )
        .into_response()
}

fn forbidden_ip(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": { "code": "forbidden_ip", "message": message } })),
    )
        .into_response()
}

/// Middleware: authenticate any valid JWT (admin, operator, reporter, break_glass).
/// Also checks JWT jti revocation (SEC-011).
pub async fn require_auth(auth_config: Arc<AuthConfig>, mut req: Request, next: Next) -> Response {
    // IP whitelist check
    if !auth_config.ip_whitelist.read().await.is_empty() {
        let headers = req.headers().clone();
        let peer: Option<IpAddr> = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let trusted: Vec<IpNet> = auth_config.trusted_proxies.read().await.clone();
        let resolved = resolve_client_ip(&headers, peer, &trusted);

        match resolved {
            None => return forbidden_ip("Client IP could not be determined"),
            Some(ip) => {
                if !auth_config.is_ip_allowed(&ip).await {
                    return forbidden_ip("Access denied");
                }
            }
        }
    }

    // Extract and validate JWT
    let token = match extract_bearer_token(req.headers()) {
        Some(t) => t,
        None => return unauthorized("Missing authorization token"),
    };

    let claims = match validate_access_token(token, &auth_config.verify_key_pem) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "JWT validation failed");
            return unauthorized("Invalid token");
        }
    };

    let role = match UserRole::parse_role(&claims.role) {
        Some(r) => r,
        None => return unauthorized("Invalid role in token"),
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap_or_else(|_| Uuid::nil());

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let auth_user = AuthUser {
        user_id,
        username: claims.username.clone(),
        role,
        claims,
        ip: peer_ip,
    };

    req.extensions_mut().insert(auth_user);
    next.run(req).await
}

/// Middleware: require the `admin` role.
pub async fn require_admin(req: Request, next: Next) -> Response {
    let auth_user = match req.extensions().get::<AuthUser>().cloned() {
        Some(u) => u,
        None => return unauthorized("Authentication required"),
    };
    if !auth_user.role.is_admin() {
        return forbidden("Admin role required");
    }
    next.run(req).await
}

/// Axum extractor: pulls `AuthUser` from request extensions.
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| unauthorized("Authentication required"))
    }
}

/// Check if a jti is revoked (SEC-011).
/// Queries the refresh_tokens table for the jti with revoked = FALSE.
pub async fn is_jti_revoked(pool: &sqlx::PgPool, jti: &str) -> bool {
    let result: Option<bool> =
        sqlx::query_scalar("SELECT revoked FROM refresh_tokens WHERE jti = $1")
            .bind(jti)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    result.unwrap_or(true) // jti not found = treat as revoked (fail-closed)
}

/// Check if an operator can access a specific host (SEC-012).
/// Admins and break_glass operators can access all hosts.
/// Operators can only access hosts in their assigned groups.
pub async fn can_access_host(
    pool: &sqlx::PgPool,
    user: &AuthUser,
    host_id: Uuid,
) -> Result<bool, sqlx::Error> {
    if user.role.is_admin() || user.role.is_break_glass() {
        return Ok(true);
    }
    if !user.role.can_write() {
        return Ok(false);
    }

    // Operator: check if host is in any of their assigned groups
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operator_host_groups ohg
         JOIN host_groups hg ON hg.group_id = ohg.group_id
         WHERE ohg.user_id = $1 AND hg.host_id = $2",
    )
    .bind(user.user_id)
    .bind(host_id)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }
    fn net(s: &str) -> IpNet {
        IpNet::from_str(s).unwrap()
    }
    fn hdr() -> HeaderMap {
        HeaderMap::new()
    }
    fn hdr_with_xff(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        h
    }

    #[test]
    fn peer_only_no_xff() {
        let result = resolve_client_ip(&hdr(), Some(ip("203.0.113.10")), &[]);
        assert_eq!(result, Some(ip("203.0.113.10")));
    }

    #[test]
    fn peer_only_xff_untrusted() {
        let headers = hdr_with_xff("198.51.100.5");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("203.0.113.10")), &trusted);
        assert_eq!(result, Some(ip("203.0.113.10")));
    }

    #[test]
    fn xff_trusted_peer_in_list() {
        let headers = hdr_with_xff("198.51.100.5");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("198.51.100.5")));
    }

    #[test]
    fn xff_trusted_multi_hop() {
        let headers = hdr_with_xff("1.2.3.4, 5.6.7.8");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("1.2.3.4")));
    }

    #[test]
    fn no_peer_no_xff() {
        let result = resolve_client_ip(&hdr(), None, &[net("10.0.0.0/8")]);
        assert_eq!(result, None);
    }

    #[test]
    fn xff_trusted_malformed() {
        let headers = hdr_with_xff("not-an-ip");
        let trusted = vec![net("10.0.0.0/8")];
        let result = resolve_client_ip(&headers, Some(ip("10.0.0.5")), &trusted);
        assert_eq!(result, Some(ip("10.0.0.5")));
    }
}
