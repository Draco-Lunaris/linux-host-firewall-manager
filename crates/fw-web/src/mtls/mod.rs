//! Per-host authorization (SEC-008): bind agent API requests to the host
//! identity established by the mTLS client certificate.

pub mod host_authz;

pub use host_authz::{ClientCertInfo, HostIdentity};
