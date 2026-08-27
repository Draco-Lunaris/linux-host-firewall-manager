//! PKI distribution — unauthenticated public endpoints (modeled on LPM's
//! `/pki/*` routes).
//!
//! `GET /api/v1/pki/crl.pem` returns the current CRL. The CRL contains only
//! serial numbers and revocation timestamps — no hostnames, no addresses — and
//! its authenticity is verifiable by any holder of the pinned CA cert, so it
//! is served without client auth or a manager login (rate-limited below).

use crate::AppState;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{extract::State, Router};

pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new().route("/pki/crl.pem", get(get_crl_pem))
}

/// `GET /api/v1/pki/crl.pem`
///
/// Returns the current Certificate Revocation List as a PEM-encoded X.509
/// CRL, signed by the manager CA, containing the serials of all revoked
/// certs that have not yet naturally expired. `Cache-Control: max-age=3600`
/// lets intermediate caches serve it: consumers refresh at least daily, so a
/// 1-hour cache balances freshness against load.
async fn get_crl_pem(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    match state.ca.generate_crl(&state.db).await {
        Ok(crl_pem) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-pem-file; charset=utf-8",
            )],
            [(header::CACHE_CONTROL, "max-age=3600")],
            crl_pem,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate CRL");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate CRL").into_response()
        }
    }
}
