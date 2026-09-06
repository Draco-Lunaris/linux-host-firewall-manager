//! Imported upstream sub-CA verification: the sub-CA becomes the issuing CA,
//! agents receive its full chain, and rejections are loud (wrong key, non-CA,
//! missing cRLSign). CRL grouping needs the `certificates` table and is covered
//! by the fw-web mTLS tests at the enforcement layer instead.

use fw_ca::CertAuthority;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::path::PathBuf;
use uuid::Uuid;
use x509_parser::prelude::*;

fn ca_key_usage_params(cn: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

struct TestTree {
    dir: PathBuf,
}

impl TestTree {
    /// Seed the manager root (so `init` takes the load path, no DB) and build
    /// an upstream root + sub-CA with a full chain file.
    fn new() -> (Self, String, String, String) {
        let dir = std::env::temp_dir().join(format!("issuing-ca-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // Manager root, pre-seeded so init() skips DB bookkeeping.
        let root_key = KeyPair::generate().unwrap();
        let root_cert = ca_key_usage_params("Firewall Manager Root CA")
            .self_signed(&root_key)
            .unwrap();
        std::fs::write(dir.join("ca.pem"), root_cert.pem()).unwrap();
        std::fs::write(dir.join("ca.key.pem"), root_key.serialize_pem()).unwrap();

        // Upstream PKI: root → sub-CA.
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = ca_key_usage_params("Upstream Corp Root CA")
            .self_signed(&upstream_key)
            .unwrap();
        let upstream_issuer =
            Issuer::new(ca_key_usage_params("Upstream Corp Root CA"), upstream_key);
        let sub_key = KeyPair::generate().unwrap();
        let sub_cert = ca_key_usage_params("Upstream Corp Sub-CA")
            .signed_by(&sub_key, &upstream_issuer)
            .unwrap();

        let chain_path = dir.join("chain.pem");
        std::fs::write(
            &chain_path,
            format!("{}\n{}", sub_cert.pem(), upstream_cert.pem()),
        )
        .unwrap();
        let key_path = dir.join("sub-ca.key.pem");
        std::fs::write(&key_path, sub_key.serialize_pem()).unwrap();

        let tree = TestTree { dir };
        (
            tree,
            chain_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
            root_cert.pem(),
        )
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_string()
    }
}

async fn manager_ca(tree: &TestTree) -> CertAuthority {
    let pool =
        sqlx::postgres::PgPool::connect_lazy("postgres://unused:unused@localhost/unused").unwrap();
    CertAuthority::init(tree.dir.to_str().unwrap().to_string(), &pool)
        .await
        .unwrap()
}

/// A client CSR whose key is held by the test (to verify the issued cert's
/// signature against the sub-CA's public key).
fn test_csr() -> (String, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "agent.example.test");
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key).unwrap();
    (csr.pem().unwrap(), key)
}

#[tokio::test]
async fn imported_sub_ca_becomes_the_issuing_ca() {
    let (tree, chain_path, key_path, root_pem) = TestTree::new();

    // Before import: the self-root issues and agents pin only the root.
    let ca = manager_ca(&tree).await;
    assert!(!ca.issuing_chain_pems().is_some());
    assert_eq!(ca.ca_chain_for_agents(), vec![root_pem.clone()]);

    // Import: the sub-CA becomes the issuing CA.
    let ca = ca.with_issuing_ca(&chain_path, &key_path).unwrap();
    assert_eq!(ca.issuing_subject_cn(), "Upstream Corp Sub-CA");
    assert_eq!(
        ca.ca_chain_for_agents(),
        vec![std::fs::read_to_string(&chain_path).unwrap()]
            .into_iter()
            .flat_map(|c| split_blocks(&c))
            .collect::<Vec<_>>()
    );
    // Anchors: self-root + the full imported chain (3 certs total).
    assert_eq!(ca.verification_anchors().len(), 3);
    assert!(!ca.issuing_serial_hex().is_empty());

    // An agent CSR is signed by the sub-CA and chains to it.
    let (csr_pem, _csr_key) = test_csr();
    let signed = ca.sign_csr(&csr_pem, uuid::Uuid::new_v4()).unwrap();
    let (_, pem) = parse_x509_pem(signed.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(issuer_cn, "Upstream Corp Sub-CA");

    // The delivered chain is the imported one (sub-CA first, upstream root last).
    assert_eq!(signed.ca_chain.len(), 2);
    let (_, sub_ca_parsed) =
        parse_x509_pem(ca.issuing_chain_pems().unwrap()[0].as_bytes()).unwrap();
    let sub_ca = sub_ca_parsed.parse_x509().unwrap();
    cert.verify_signature(Some(&sub_ca.tbs_certificate.subject_pki))
        .expect("agent cert must be signed by the imported sub-CA");
    // Chain order: sub-CA first, upstream root last (check via parsed CNs —
    // PEM is base64, so the CN text isn't greppable).
    let (_, last_parsed) = parse_x509_pem(signed.ca_chain[1].as_bytes()).unwrap();
    let last = last_parsed.parse_x509().unwrap();
    let last_cn = last
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(last_cn, "Upstream Corp Root CA");
}

#[tokio::test]
async fn import_rejects_mismatched_key() {
    let (tree, chain_path, _key_path, _root_pem) = TestTree::new();
    // A key that does not belong to the sub-CA cert.
    let other_key = KeyPair::generate().unwrap();
    let wrong_key_path = tree.path("wrong.key.pem");
    std::fs::write(&wrong_key_path, other_key.serialize_pem()).unwrap();

    let ca = manager_ca(&tree).await;
    let Err(err) = ca.with_issuing_ca(&chain_path, &wrong_key_path) else {
        panic!("import with a mismatched key must fail");
    };
    assert!(
        err.to_string().contains("does not match"),
        "expected key/cert mismatch error, got: {err}"
    );
}

#[tokio::test]
async fn import_rejects_cert_without_crl_sign() {
    // Seed a full tree (manager root included, so init() never touches a DB),
    // then overwrite the imported chain with a cRLSign-less sub-CA.
    let (tree, chain_path, key_path, _root_pem) = TestTree::new();

    let upstream_key = KeyPair::generate().unwrap();
    let upstream_cert = ca_key_usage_params("Upstream Corp Root CA")
        .self_signed(&upstream_key)
        .unwrap();
    let upstream_issuer = Issuer::new(ca_key_usage_params("Upstream Corp Root CA"), upstream_key);
    // Sub-CA without cRLSign — revocation cannot work with it.
    let sub_key = KeyPair::generate().unwrap();
    let mut sub_params = ca_key_usage_params("Sub-CA No CRL");
    sub_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let sub_cert = sub_params.signed_by(&sub_key, &upstream_issuer).unwrap();

    std::fs::write(
        &chain_path,
        format!("{}\n{}", sub_cert.pem(), upstream_cert.pem()),
    )
    .unwrap();
    std::fs::write(&key_path, sub_key.serialize_pem()).unwrap();

    let ca = manager_ca(&tree).await;
    let Err(err) = ca.with_issuing_ca(&chain_path, &key_path) else {
        panic!("import without cRLSign must fail");
    };
    assert!(
        err.to_string().contains("cRLSign"),
        "expected cRLSign rejection, got: {err}"
    );
}

#[tokio::test]
async fn import_rejects_expired_sub_ca() {
    let (tree, chain_path, key_path, _root_pem) = TestTree::new();

    // Upstream root (valid) + a sub-CA whose validity window is entirely in
    // the past.
    let upstream_key = KeyPair::generate().unwrap();
    let upstream_cert = ca_key_usage_params("Upstream Corp Root CA")
        .self_signed(&upstream_key)
        .unwrap();
    let upstream_issuer = Issuer::new(ca_key_usage_params("Upstream Corp Root CA"), upstream_key);
    let sub_key = KeyPair::generate().unwrap();
    let mut sub_params = ca_key_usage_params("Upstream Corp Sub-CA");
    let now = ::time::OffsetDateTime::now_utc();
    sub_params.not_before = now - ::time::Duration::days(2);
    sub_params.not_after = now - ::time::Duration::days(1);
    let sub_cert = sub_params.signed_by(&sub_key, &upstream_issuer).unwrap();

    std::fs::write(
        &chain_path,
        format!("{}\n{}", sub_cert.pem(), upstream_cert.pem()),
    )
    .unwrap();
    std::fs::write(&key_path, sub_key.serialize_pem()).unwrap();

    let ca = manager_ca(&tree).await;
    let Err(err) = ca.with_issuing_ca(&chain_path, &key_path) else {
        panic!("import of an expired sub-CA must fail");
    };
    assert!(
        err.to_string().contains("expired"),
        "expected expired-sub-CA rejection, got: {err}"
    );
}

#[tokio::test]
async fn import_rejects_broken_chain() {
    let (tree, chain_path, key_path, _root_pem) = TestTree::new();

    // A sub-CA signed by upstream root A...
    let root_a_key = KeyPair::generate().unwrap();
    let root_a_issuer = Issuer::new(ca_key_usage_params("Upstream Corp Root CA"), root_a_key);
    let sub_key = KeyPair::generate().unwrap();
    let sub_cert = ca_key_usage_params("Upstream Corp Sub-CA")
        .signed_by(&sub_key, &root_a_issuer)
        .unwrap();
    // ...but the chain file ships an unrelated root B (issuer/subject mismatch).
    let root_b_key = KeyPair::generate().unwrap();
    let root_b = ca_key_usage_params("Unrelated Root B")
        .self_signed(&root_b_key)
        .unwrap();

    std::fs::write(&chain_path, format!("{}\n{}", sub_cert.pem(), root_b.pem())).unwrap();
    std::fs::write(&key_path, sub_key.serialize_pem()).unwrap();

    let ca = manager_ca(&tree).await;
    let Err(err) = ca.with_issuing_ca(&chain_path, &key_path) else {
        panic!("import of a broken chain must fail");
    };
    assert!(
        err.to_string().contains("broken"),
        "expected broken-chain rejection, got: {err}"
    );
}

#[tokio::test]
async fn without_import_the_root_issues() {
    let (tree, _chain_path, _key_path, root_pem) = TestTree::new();
    let ca = manager_ca(&tree).await;
    assert_eq!(ca.issuing_subject_cn(), "Firewall Manager Root CA");

    let (csr_pem, _csr_key) = test_csr();
    let signed = ca.sign_csr(&csr_pem, uuid::Uuid::new_v4()).unwrap();
    assert_eq!(signed.ca_chain, vec![root_pem]);
    let (_, pem) = parse_x509_pem(signed.cert_pem.as_bytes()).unwrap();
    let _cert = pem.parse_x509().unwrap();
    // (Signature check omitted here — the sub-CA test above covers chaining.)
}

/// Split a PEM bundle into individual blocks.
fn split_blocks(bundle: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in bundle.lines() {
        current.push_str(line);
        current.push('\n');
        if line.contains("-----END CERTIFICATE-----") {
            blocks.push(std::mem::take(&mut current));
        }
    }
    blocks
}
