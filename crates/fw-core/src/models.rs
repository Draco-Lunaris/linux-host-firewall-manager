use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::types::Json;
use uuid::Uuid;

// ============================================================
// Enum types (match PostgreSQL ENUM types)
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "firewall_action", rename_all = "lowercase")]
pub enum FirewallAction {
    Allow,
    Deny,
    Reject,
    Limit,
    Masquerade,
}

impl FirewallAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
            Self::Limit => "limit",
            Self::Masquerade => "masquerade",
        }
    }
}

/// A policy set's default input/output policy (applied by the agent as
/// `ufw default <policy> incoming|outgoing`). NULL at the DB level means
/// "system default" — the agent leaves the direction's default untouched
/// (preserving the pre-existing reset-based behavior). The enum itself only
/// carries the three explicit values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "firewall_default_policy", rename_all = "lowercase")]
pub enum FirewallDefaultPolicy {
    Allow,
    Deny,
    Reject,
}

impl FirewallDefaultPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "firewall_direction", rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
    Forward,
}

impl FirewallDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
            Self::Forward => "forward",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
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

impl FirewallProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Gre => "gre",
            Self::Esp => "esp",
            Self::Ah => "ah",
            Self::Sctp => "sctp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "user_role", rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Operator,
    Reporter,
    BreakGlassOperator,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Reporter => "reporter",
            Self::BreakGlassOperator => "break_glass_operator",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "host_health_status", rename_all = "lowercase")]
pub enum HostHealthStatus {
    Pending,
    Healthy,
    Degraded,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "cert_status", rename_all = "lowercase")]
pub enum CertStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "snake_case")]
pub enum AuthProvider {
    Local,
    AzureSso,
    Keycloak,
    Oidc,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    UserLogin,
    UserLogout,
    UserLoginFailed,
    UserCreated,
    UserDeleted,
    UserUpdated,
    HostRegistered,
    HostRemoved,
    GroupCreated,
    GroupDeleted,
    GroupMembershipChanged,
    FirewallJobCreated,
    FirewallJobCancelled,
    FirewallJobRollback,
    MaintenanceWindowCreated,
    MaintenanceWindowUpdated,
    MaintenanceWindowDeleted,
    CertificateIssued,
    CertificateRenewed,
    CertificateRevoked,
    CertificateDownloaded,
    ConfigChanged,
    DiscoveryScanStarted,
    AuditIntegrityVerified,
    EmailNotificationSent,
    FirewallJobCompleted,
    FirewallJobFailed,
    MaintenanceWindowReminder,
    RuleCreated,
    RuleUpdated,
    RuleDeleted,
    PolicySetCreated,
    PolicySetChanged,
    PolicyAssigned,
    PolicyUnassigned,
    RuleDeployed,
    RuleRollback,
    DriftDetected,
    BackendChanged,
    BreakGlassUsed,
    EnrollmentTokenIssued,
    EnrollmentTokenUsed,
    EnrollmentTokenRevoked,
    HostEnrolled,
    CaIntermediateIssued,
    CaIntermediateRevoked,
    AuditAnchorMismatch,
    PolicyForceCheckin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "policy_decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    AutoApproved,
    Flagged,
    Rejected,
    ApprovedByAdmin,
    DeniedByAdmin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "pending_action_type", rename_all = "snake_case")]
pub enum PendingActionType {
    ApplyRules,
    Rollback,
    SafeModeOn,
    SafeModeOff,
    ReloadConfig,
    AgentUpgrade,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "pending_action_status", rename_all = "lowercase")]
pub enum PendingActionStatus {
    Queued,
    Pushing,
    Delivered,
    Executed,
    Failed,
    Expired,
}

// ============================================================
// Core domain models
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
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
    pub comment: String,
    pub log: bool,
    pub priority: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Column list for `firewall_rules` with the inet CIDR columns cast to text.
/// sqlx cannot decode `inet` into the model's `Option<String>` fields, so
/// every SELECT/RETURNING over `firewall_rules` must use this list (casting
/// `src_cidr`/`dst_cidr` to text and aliasing them back to the column name for
/// `FromRow`) instead of `*`. INSERT/UPDATE binds of those columns must use
/// `$N::inet` for the reverse direction (text → inet).
pub const FIREWALL_RULE_COLS: &str = "id, name, description, action, direction, \
    protocol, src_cidr::text AS src_cidr, src_port_start, src_port_end, \
    dst_cidr::text AS dst_cidr, dst_port_start, dst_port_end, interface_in, \
    interface_out, comment, log, priority, created_by, created_at, updated_at";

/// Same as `FIREWALL_RULE_COLS` but with the `r.` table alias, for joins that
/// select from `firewall_rules r` (e.g. policy-set rule listings).
pub const FIREWALL_RULE_COLS_R: &str = "r.id, r.name, r.description, r.action, \
    r.direction, r.protocol, r.src_cidr::text AS src_cidr, r.src_port_start, \
    r.src_port_end, r.dst_cidr::text AS dst_cidr, r.dst_port_start, \
    r.dst_port_end, r.interface_in, r.interface_out, r.comment, r.log, \
    r.priority, r.created_by, r.created_at, r.updated_at";

// ============================================================
// Drift hash — shared by the manager and the agent
// ============================================================

/// The canonical rule fields used to compute the drift hash. Both the
/// manager (from the assigned policy rules) and the agent (from the rules it
/// last applied) build these so the two sides hash the *same representation*
/// — the agent reports this hash on check-in, not its backend's live-status
/// text hash, so the comparison is apples-to-apples and converges.
#[derive(Clone, Copy)]
pub struct RuleHashParts<'a> {
    pub id: &'a Uuid,
    pub action: &'a str,
    pub direction: &'a str,
    pub protocol: &'a str,
    pub src_cidr: Option<&'a str>,
    pub dst_cidr: Option<&'a str>,
    pub dst_port_start: Option<i32>,
}

/// SHA-256 over a ruleset's canonical fields (id, action, direction,
/// protocol, src_cidr, dst_cidr, dst_port_start). Stable across the manager
/// and the agent: the manager computes the *expected* hash of the assigned
/// policy; the agent computes the hash of the rules it applied. Equal hashes
/// ⇒ the agent is running the current policy ⇒ no re-apply.
pub fn compute_rules_hash(rules: &[RuleHashParts<'_>]) -> String {
    let mut hasher = sha2::Sha256::new();
    for r in rules {
        hasher.update(r.id.as_bytes());
        hasher.update(r.action.as_bytes());
        hasher.update(r.direction.as_bytes());
        hasher.update(r.protocol.as_bytes());
        if let Some(c) = r.src_cidr {
            hasher.update(c.as_bytes());
        }
        if let Some(c) = r.dst_cidr {
            hasher.update(c.as_bytes());
        }
        if let Some(p) = r.dst_port_start {
            hasher.update(p.to_le_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallPolicySet {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Default policy for the input direction (NULL = system default — agent
    /// does not call `ufw default incoming`).
    pub default_input_policy: Option<FirewallDefaultPolicy>,
    /// Default policy for the output direction (NULL = system default — agent
    /// does not call `ufw default outgoing`).
    pub default_output_policy: Option<FirewallDefaultPolicy>,
}

/// A reusable, ordered collection of rules — the middle tier of the containment
/// model. A rule belongs to exactly one group (1:1); a policy set collects an
/// ordered list of groups. Editing a rule in a group propagates to every policy
/// set that includes the group.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallRuleGroup {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Membership of a rule group in a policy set, with the group's position in the
/// set's apply order. M:N (groups <-> sets).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallPolicySetRuleGroup {
    pub policy_set_id: Uuid,
    pub rule_group_id: Uuid,
    pub set_group_order: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HostPolicyAssignment {
    pub host_id: Uuid,
    pub policy_set_id: Uuid,
    pub assigned_by: Option<Uuid>,
    pub assigned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DriftSnapshot {
    pub id: Uuid,
    pub host_id: Uuid,
    pub snapshot_hash: String,
    pub rule_count: i32,
    pub captured_at: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Host {
    pub id: Uuid,
    pub fqdn: String,
    pub ip_address: String,
    pub display_name: String,
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub arch: Option<String>,
    pub agent_version: Option<String>,
    pub health_status: HostHealthStatus,
    pub last_health_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub agent_port: i32,
    pub notes: String,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Security columns (added by later migrations)
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: UserRole,
    pub auth_provider: AuthProvider,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub force_password_reset: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Certificate {
    pub id: Uuid,
    pub host_id: Option<Uuid>,
    pub serial_number: String,
    pub common_name: String,
    pub status: CertStatus,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub cert_pem: String,
    pub ca_tier: String,
    pub parent_cert_id: Option<Uuid>,
}

// ============================================================
// Security models
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProtectedCidr {
    pub host_id: Uuid,
    pub cidr: String,
    pub label: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RulePolicyDecision {
    pub id: Uuid,
    pub rule_id: Option<Uuid>,
    pub policy_set_id: Option<Uuid>,
    pub decision: PolicyDecision,
    pub reason: String,
    pub reviewer_id: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EnrollmentToken {
    pub token_hash: String,
    pub host_fqdn: String,
    pub host_ip: Option<String>,
    pub created_by: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EnrollmentRequest {
    pub id: Uuid,
    pub machine_id: String,
    pub fqdn: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub os_details: Json<serde_json::Value>,
    pub polling_token: String,
    /// The agent's CSR (PEM), captured at submission so the manager can sign it
    /// on approval. NULL for legacy rows.
    pub csr: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditAnchor {
    pub id: Uuid,
    pub chain_head: String,
    pub anchored_at: DateTime<Utc>,
    pub anchor_type: String,
    pub anchor_ref: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OperatorHostGroup {
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub assigned_at: DateTime<Utc>,
}

// ============================================================
// PKI / enrollment bundles (not DB tables — wire types)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiBundle {
    pub ca_chain: Vec<String>,
    pub server_cert: String,
    pub crl_pem: Option<String>,
    #[serde(default)]
    pub pull_config: Option<PullConfigBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullConfigBundle {
    pub check_in_interval_secs: i32,
    pub push_enabled: bool,
    pub config_version: i32,
    /// Base URL of the manager's agent mTLS API (e.g. "https://mgr:8443").
    /// The agent appends the endpoint paths (`/api/v1/agent/check-in`, …) —
    /// this is a *base*, not the full check-in URL, so all four agent
    /// endpoints (check-in, check-in/result, policy, events) share it.
    pub manager_agent_url: String,
}

// ============================================================
// Pull model: check-ins, config overrides, pending actions
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentCheckIn {
    pub id: Uuid,
    pub host_id: Uuid,
    pub rules_hash: String,
    pub agent_version: String,
    pub backend_type: String,
    pub os_info: serde_json::Value,
    pub uptime_seconds: i64,
    pub config_version: i32,
    pub pending_results: serde_json::Value,
    pub checked_in_at: chrono::DateTime<chrono::Utc>,
    // Apply-result fields (written by POST /check-in/result; NULL until a result arrives)
    pub apply_success: Option<bool>,
    pub apply_error: Option<String>,
    pub applied_rule_count: Option<i32>,
    pub applied_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HostConfigOverride {
    pub host_id: Uuid,
    pub check_in_interval_secs: i32,
    pub push_enabled: bool,
    pub safe_mode_enabled: bool,
    pub backend_override: Option<String>,
    pub config_version: i32,
    pub last_known_good_hash: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PendingAction {
    pub id: Uuid,
    pub host_id: Uuid,
    pub action_type: PendingActionType,
    pub payload: serde_json::Value,
    pub reason: String,
    pub priority: i32,
    pub status: PendingActionStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub first_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub executed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::FirewallDefaultPolicy;

    #[test]
    fn default_policy_serde_is_lowercase_round_trip() {
        // The LHFM JSON-enum-casing contract: JSON uses lowercase variants
        // matching the DB enum and TS. A value must round-trip through serde.
        for v in [
            FirewallDefaultPolicy::Allow,
            FirewallDefaultPolicy::Deny,
            FirewallDefaultPolicy::Reject,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(json, format!("\"{}\"", v.as_str()));
            let back: FirewallDefaultPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
        // None serializes to null (system default at the API boundary).
        let none_json = serde_json::to_string(&Option::<FirewallDefaultPolicy>::None).unwrap();
        assert_eq!(none_json, "null");
    }
}
