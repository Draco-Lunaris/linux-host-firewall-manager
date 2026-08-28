//! SEC-008 verification: the agent mTLS listener binds the request's host
//! identity to the verified client certificate, and rejects connections that
//! present no client cert.
//!
//! This is a self-contained network test — no Postgres. It uses a minimal
//! `Router<()>` with a `whoami` handler that echoes `HostIdentity`, exercising
//! the same `ConnectInfo<ClientCertInfo>` → `HostIdentity` path the real
//! `agent_api` handlers use.

use ::time::OffsetDateTime;
use axum::serve::Listener;
use axum::{routing::get, Router};
use fw_web::agent_listener::{build_agent_server_config, AgentTlsListener};
use fw_web::mtls::{ClientCertInfo, HostIdentity};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::time::Duration;
use uuid::Uuid;
use x509_parser::prelude::*;

/// Echo the cert-bound host_id. No state, no DB.
async fn whoami(host: HostIdentity) -> String {
    host.0.to_string()
}

/// Generate a test CA, a server cert (manager identity), and a client cert
/// whose CN is a host_id UUID — mirroring what the real CA issues. Returns the
/// CA signing objects too, so tests can sign CRLs revoking the client cert.
#[allow(clippy::type_complexity)]
fn test_pki() -> (
    String,
    rcgen::Certificate,
    KeyPair,
    String,
    String,
    String,
    String,
    Uuid,
) {
    let host_id = Uuid::new_v4();

    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "LHFM Test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "manager");
    let server_key = KeyPair::generate().unwrap();
    let server_pem = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap()
        .pem();
    let server_key_pem = server_key.serialize_pem();

    let mut client_params = CertificateParams::new(Vec::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host_id.to_string());
    client_params.distinguished_name = dn;
    client_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let client_key = KeyPair::generate().unwrap();
    let client_pem = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap()
        .pem();
    let client_key_pem = client_key.serialize_pem();

    (
        ca_pem,
        ca_cert,
        ca_key,
        server_pem,
        server_key_pem,
        client_pem,
        client_key_pem,
        host_id,
    )
}

#[tokio::test]
async fn mtls_binds_host_id_from_client_cert() {
    // The test process doesn't run main(), so install the rustls crypto provider
    // (main.rs does this at startup). The sibling test may have won the race.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (
        ca_pem,
        _ca_cert,
        _ca_key,
        server_pem,
        server_key_pem,
        client_pem,
        client_key_pem,
        host_id,
    ) = test_pki();

    let server_config =
        build_agent_server_config(&ca_pem, &server_pem, &server_key_pem, &[]).unwrap();
    let shared_acceptor = std::sync::Arc::new(std::sync::RwLock::new(
        tokio_rustls::TlsAcceptor::from(server_config),
    ));
    let listener = AgentTlsListener::new("127.0.0.1:0".parse().unwrap(), shared_acceptor)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().remote_addr;

    let app = Router::new().route("/api/v1/agent/whoami", get(whoami));
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientCertInfo>(),
        )
        .await;
    });

    let url = format!("https://{addr}/api/v1/agent/whoami");

    // 1) A client with a valid CA-signed cert (CN=host_id) is bound to that host_id.
    let identity =
        reqwest::Identity::from_pem(format!("{client_pem}\n{client_key_pem}").as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .identity(identity)
        // We are verifying CLIENT-cert binding, not the server cert, so accept
        // the self-signed test server cert.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client.get(&url).send().await.expect("valid-cert request");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(
        body,
        host_id.to_string(),
        "whoami must return the cert CN host_id"
    );

    // 2) A client with NO cert is rejected at the TLS handshake (fail-closed).
    let no_cert_client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let result = no_cert_client.get(&url).send().await;
    assert!(
        result.is_err(),
        "a connection without a client cert must be rejected at the TLS handshake"
    );

    server.abort();
}

/// CRL enforcement (deferred-hardening follow-up): a client cert whose serial
/// appears in the CA-signed CRL must fail the TLS handshake; a cert with no
/// CRL entry (unknown revocation status) must still connect —
/// `allow_unknown_revocation_status` is required so certs issued before leaf
/// persistence (migration 035) aren't locked out.
#[tokio::test]
async fn mtls_rejects_crl_revoked_client_cert() {
    // The other test in this binary may have installed it already.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (ca_pem, ca_cert, ca_key, server_pem, server_key_pem, client_pem, client_key_pem, _host_id) =
        test_pki();

    // Revoke the client cert's serial: parse it from the issued cert, then
    // build a CRL signed by the same CA containing exactly that serial.
    let (_, client_cert_pem) = parse_x509_pem(client_pem.as_bytes()).unwrap();
    let client_cert = client_cert_pem.parse_x509().unwrap();
    let crl_pem = rcgen::CertificateRevocationListParams {
        this_update: OffsetDateTime::now_utc() - ::time::Duration::hours(1),
        next_update: OffsetDateTime::now_utc() + ::time::Duration::hours(24),
        crl_number: rcgen::SerialNumber::from_slice(&[1]),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(client_cert.raw_serial()),
            revocation_time: OffsetDateTime::now_utc(),
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&ca_cert, &ca_key)
    .unwrap()
    .pem()
    .unwrap();

    let revoked_config =
        build_agent_server_config(&ca_pem, &server_pem, &server_key_pem, &[crl_pem]).unwrap();
    let revoked_acceptor = std::sync::Arc::new(std::sync::RwLock::new(
        tokio_rustls::TlsAcceptor::from(revoked_config),
    ));
    let listener = AgentTlsListener::new("127.0.0.1:0".parse().unwrap(), revoked_acceptor)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().remote_addr;

    let app = Router::new().route("/api/v1/agent/whoami", get(whoami));
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientCertInfo>(),
        )
        .await;
    });

    // 1) The revoked cert fails at the TLS handshake.
    let identity =
        reqwest::Identity::from_pem(format!("{client_pem}\n{client_key_pem}").as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .identity(identity)
        // Verifying the CLIENT-cert revocation, not the server cert.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let result = client
        .get(format!("https://{addr}/api/v1/agent/whoami"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "a CRL-revoked client cert must be rejected at the TLS handshake"
    );

    // 2) A cert with no CRL entry (unknown revocation status) still connects:
    //    a second, unrevoked client cert issued by the same CA.
    let other_id = Uuid::new_v4();
    let mut other_params = CertificateParams::new(Vec::new()).unwrap();
    let mut other_dn = DistinguishedName::new();
    other_dn.push(DnType::CommonName, other_id.to_string());
    other_params.distinguished_name = other_dn;
    other_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let other_key = KeyPair::generate().unwrap();
    let other_pem = other_params
        .signed_by(&other_key, &ca_cert, &ca_key)
        .unwrap()
        .pem();
    let other_identity = reqwest::Identity::from_pem(
        format!("{other_pem}\n{}", other_key.serialize_pem()).as_bytes(),
    )
    .unwrap();
    let other_client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .identity(other_identity)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = other_client
        .get(format!("https://{addr}/api/v1/agent/whoami"))
        .send()
        .await
        .expect("unknown-revocation-status cert must still connect");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), other_id.to_string());

    server.abort();
}
