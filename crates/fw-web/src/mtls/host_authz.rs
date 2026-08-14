//! Per-host authorization (SEC-008): bind agent API requests to the host
//! identity established by the mTLS client certificate.
//!
//! The agent mTLS listener (see `crate::agent_listener`) parses the verified
//! client cert's CN into a `host_id` UUID at accept time and carries it to
//! handlers via `ConnectInfo<ClientCertInfo>`. The `HostIdentity` extractor
//! reads it. The cert — not the request body — is the host identity.

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{request::Parts, StatusCode};
use std::net::SocketAddr;
use uuid::Uuid;

/// Per-connection identity carried from the agent mTLS listener.
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// The host_id parsed from the verified client certificate's CN.
    pub host_id: Uuid,
    /// The remote TCP address of the agent.
    pub remote_addr: SocketAddr,
}

/// Extractor yielding the host_id bound to the request via the mTLS client cert.
///
/// Only present on the agent listener (served with
/// `into_make_service_with_connect_info::<ClientCertInfo>`); absent on the human
/// UI listener, so it 401s if a handler behind it is reached without mTLS.
pub struct HostIdentity(pub Uuid);

impl<S> FromRequestParts<S> for HostIdentity
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let info = parts
            .extensions
            .get::<ConnectInfo<ClientCertInfo>>()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "no mTLS client identity on this connection".to_string(),
            ))?;
        Ok(HostIdentity(info.0.host_id))
    }
}
