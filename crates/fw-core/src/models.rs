use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

// ============================================================
// Enum types (match PostgreSQL ENUM types)
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "firewall_direction", rename_all = "lowercase")]
pub enum FirewallDirection {
    In,
    Out,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallPolicySet {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallPolicySetRule {
    pub policy_set_id: Uuid,
    pub rule_id: Uuid,
    pub rule_order: i32,
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
