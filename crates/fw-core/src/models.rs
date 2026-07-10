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
#[sqlx(type_name = "job_status", rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "job_kind", rename_all = "lowercase")]
pub enum JobKind {
    RuleApply,
    RuleRemove,
    Reboot,
    Rollback,
    SelfUpgrade,
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
#[sqlx(type_name = "window_recurrence", rename_all = "lowercase")]
pub enum WindowRecurrence {
    Once,
    Daily,
    Weekly,
    Monthly,
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
pub struct FirewallJob {
    pub id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
    pub created_by_user_id: Option<Uuid>,
    pub parent_job_id: Option<Uuid>,
    pub maintenance_window_id: Option<Uuid>,
    pub immediate: bool,
    pub policy_set_id: Option<Uuid>,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub auto_apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirewallJobHost {
    pub id: Uuid,
    pub job_id: Uuid,
    pub host_id: Uuid,
    pub status: JobStatus,
    pub agent_job_id: Option<String>,
    pub retry_count: i32,
    pub output: String,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MaintenanceWindow {
    pub id: Uuid,
    pub host_id: Uuid,
    pub label: String,
    pub recurrence: WindowRecurrence,
    pub start_at: DateTime<Utc>,
    pub duration_minutes: i32,
    pub recurrence_day: Option<i32>,
    pub enabled: bool,
    pub auto_apply: bool,
    pub notify_before_minutes: Option<i32>,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
pub struct HostApplyLock {
    pub host_id: Uuid,
    pub locked_by_job: Option<Uuid>,
    pub locked_at: DateTime<Utc>,
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
    pub manager_check_in_url: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HostConfigOverride {
    pub host_id: Uuid,
    pub check_in_interval_secs: i32,
    pub push_enabled: bool,
    pub safe_mode_enabled: bool,
    pub backend_override: Option<String>,
    pub config_version: i32,
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
