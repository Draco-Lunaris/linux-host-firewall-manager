//! Agent mTLS listener (SEC-008).
//!
//! axum-server 0.7 does not expose the verified client certificate to handlers,
//! so the agent API is served with a custom `axum::serve::Listener` instead.
//! `AgentTlsListener` wraps a `TcpListener` + a `tokio_rustls::TlsAcceptor`
//! built from a `rustls::server::ServerConfig` with a **mandatory**
//! `WebPkiClientVerifier` pinned to the manager CA root. Connections without a
//! CA-signed client cert fail the TLS handshake and are dropped before any
//! handler runs (fail-closed at the TLS layer).
//!
//! On a successful handshake the listener reads the peer certificate, parses its
//! CN into a `host_id` UUID, and returns `(TlsStream, ClientCertInfo)`. axum's
//! blanket `Connected<IncomingStream<'_, L>> for L::Addr` impl then surfaces it
//! to handlers as `ConnectInfo<ClientCertInfo>` — no manual `Connected` impl.

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use rustls::pki_types::CertificateDer;
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use x509_parser::prelude::*;

use crate::mtls::host_authz::ClientCertInfo;

/// Surface the per-connection `ClientCertInfo` to handlers as
/// `ConnectInfo<ClientCertInfo>`. (The blanket `Connected` impl only covers
/// `TapIo`-wrapped listeners, so an explicit impl is required here.)
impl<'a> Connected<IncomingStream<'a, AgentTlsListener>> for ClientCertInfo {
    fn connect_info(stream: IncomingStream<'a, AgentTlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// A `Listener` that performs a mandatory-mTLS handshake and carries the
/// cert-bound host_id into each request.
pub struct AgentTlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl AgentTlsListener {
    pub async fn new(addr: SocketAddr, server_config: Arc<ServerConfig>) -> std::io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp,
            acceptor: TlsAcceptor::from(server_config),
        })
    }
}

impl Listener for AgentTlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = ClientCertInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, remote_addr) = match self.tcp.accept().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, "agent listener: tcp accept failed");
                    continue;
                }
            };

            let tls_stream = match self.acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    // No client cert (or otherwise invalid) => handshake rejected.
                    tracing::warn!(error = %e, "agent mTLS handshake rejected");
                    continue;
                }
            };

            let host_id = match tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(parse_host_id)
            {
                Some(id) => id,
                None => {
                    tracing::warn!("agent mTLS: client cert CN is not a host_id; dropping");
                    continue;
                }
            };

            return (
                tls_stream,
                ClientCertInfo {
                    host_id,
                    remote_addr,
                },
            );
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        // `Listener::Addr` is shared between per-connection info and `local_addr`.
        // There is no host_id for the listener's own address, so use a nil UUID.
        let remote_addr = self.tcp.local_addr()?;
        Ok(ClientCertInfo {
            host_id: Uuid::nil(),
            remote_addr,
        })
    }
}

/// Parse the CN of a client certificate into a host_id UUID.
fn parse_host_id(cert: &CertificateDer<'_>) -> Option<Uuid> {
    let parsed = X509Certificate::from_der(cert.as_ref()).ok()?.1;
    let cn = parsed.subject().iter_common_name().next()?;
    Uuid::parse_str(cn.as_str().ok()?).ok()
}

/// Build the agent-listener `ServerConfig`: mandatory client-cert verification
/// pinned to the manager CA root, plus the manager's own server cert/key.
pub fn build_agent_server_config(
    ca_root_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<Arc<ServerConfig>, std::io::Error> {
    let mut roots = RootCertStore::empty();
    let mut ca_rd = ca_root_pem.as_bytes();
    for cert in rustls_pemfile::certs(&mut ca_rd) {
        roots.add(cert.map_err(io_err)?).map_err(io_err)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| io_err(format!("client verifier build failed: {e}")))?;

    let mut cert_rd = server_cert_pem.as_bytes();
    let server_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_rd)
        .collect::<Result<_, _>>()
        .map_err(io_err)?;
    let mut key_rd = server_key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_rd)
        .map_err(io_err)?
        .ok_or_else(|| io_err("no private key in agent TLS key file"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|e| io_err(format!("server config build failed: {e}")))?;
    Ok(Arc::new(config))
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
