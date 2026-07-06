use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "firewall_action", rename_all = "lowercase")]
pub enum FirewallAction {
    Allow,
    Deny,
    Reject,
    Limit,
    Masquerade,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "firewall_direction", rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "firewall_protocol", rename_all = "lowercase")]
pub enum FirewallProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Gre,
    Esp,
    Ah,
    Sctp,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallRule {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub action: FirewallAction,
    pub direction: FirewallDirection,
    pub protocol: FirewallProtocol,
    pub src_cidr: Option<String>,
    pub src_port_start: Option<i32>,
    pub src_port_end: Option<i32>,
    pub dst_cidr: Option<String>,
    pub dst_port_start: Option<i32>,
    pub dst_port_end: Option<i32>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    pub log: bool,
    pub priority: i32,
    pub created_by: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallPolicySet {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HostPolicyAssignment {
    pub host_id: i64,
    pub policy_set_id: i64,
    pub assigned_by: Option<i64>,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DriftSnapshot {
    pub host_id: i64,
    pub snapshot_hash: String,
    pub rule_count: i32,
    pub captured_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Host {
    pub id: i64,
    pub fqdn: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os_info: Option<String>,
    pub backend_active: Option<String>,
    pub container_runtime: Option<String>,
    pub agent_binary_hash: Option<String>,
    pub agent_version: Option<String>,
    pub crl_status: Option<String>,
    pub gpg_key_status: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallJob {
    pub id: i64,
    pub job_kind: String,
    pub policy_set_id: Option<i64>,
    pub status: String,
    pub created_by: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallJobHost {
    pub job_id: i64,
    pub host_id: i64,
    pub status: String,
    pub error_message: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiBundle {
    pub ca_chain: Vec<String>,
    pub server_cert: String,
    pub crl_pem: Option<String>,
    pub repo_config: Option<RepoConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    pub gpg_public_key: String,
    pub sources_config: serde_json::Value,
    pub distro_id: String,
    pub keyring_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub id: i64,
    pub fqdn: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os_details: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedCidr {
    pub host_id: i64,
    pub cidr: String,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "policy_decision", rename_all = "lowercase")]
pub enum PolicyDecision {
    AutoApproved,
    Flagged,
    Rejected,
    ApprovedByAdmin,
    DeniedByAdmin,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RulePolicyDecision {
    pub id: i64,
    pub rule_id: Option<i64>,
    pub policy_set_id: Option<i64>,
    pub decision: PolicyDecision,
    pub reason: Option<String>,
    pub reviewer_id: Option<i64>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
