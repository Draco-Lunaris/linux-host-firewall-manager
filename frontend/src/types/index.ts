// Core TypeScript types — expanded per milestone

export type UserRole = 'admin' | 'operator' | 'reporter'
export type AuthProvider = 'local' | 'azure_sso' | 'keycloak' | 'oidc'
export type HostHealthStatus = 'pending' | 'healthy' | 'degraded' | 'unreachable'

export interface ApiError {
  error: {
    code: string
    message: string
    request_id?: string
    details?: unknown
  }
}

export interface Host {
  id: string
  fqdn: string
  ip_address: string
  display_name: string
  health_status: HostHealthStatus
  os_family?: string
  os_name?: string
  arch?: string
  agent_version?: string
  agent_port?: number
  notes?: string
  last_health_at?: string
  last_sync_at?: string
  registered_at: string
  updated_at?: string
  health_check_status?: 'all_healthy' | 'some_unhealthy' | 'none'
  container_runtime?: string | null
}

export interface CreateHostRequest {
  fqdn: string
  display_name?: string
  agent_port?: number
  notes?: string
  group_ids?: string[]
}

export interface UpdateHostRequest {
  fqdn?: string
  ip_address?: string
  display_name?: string
}

export interface Group {
  id: string
  name: string
  description: string
  created_at: string
}

export interface User {
  id: string
  username: string
  display_name: string
  email: string
  role: UserRole
  auth_provider: AuthProvider
  mfa_enabled: boolean
  is_active: boolean
  force_password_reset: boolean
  last_login_at?: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface AdminResetPasswordRequest {
  new_password: string
  force_password_reset?: boolean
}

export interface UpdateUserRequest {
  display_name?: string
  email?: string
  role?: string
  is_active?: boolean
  force_password_reset?: boolean
}

export interface CreateUserRequest {
  username: string
  display_name?: string
  email: string
  role: string
  password: string
}

export interface FleetStatus {
  total_hosts: number
  healthy: number
  degraded: number
  unreachable: number
  pending: number
  total_rules: number
  policy_sets: number
  /** Distinct hosts that reported a rules-hash mismatch on check-in in the last 24h. */
  hosts_in_drift: number
  /** Check-ins received in the last 15 minutes (pull-model liveness). */
  recent_check_ins: number
}

// ── Certificates (M8) ────────────────────────────────────────────────────────

export type CertStatus = 'active' | 'revoked' | 'expired'

export interface Certificate {
  id: string
  host_id: string | null   // null = root CA cert
  serial_number: string
  common_name: string
  status: CertStatus
  issued_at: string
  expires_at: string
  revoked_at: string | null
  cert_pem: string
}

export interface IssuedCert {
  cert_pem: string
  key_pem: string
  serial_number: string
  expires_at: string
  server_cert_pem: string
  server_key_pem: string
  server_serial_number: string
  ca_root_pem: string
}

// ── Settings (M10) ──────────────────────────────────────────────────────────

/** @deprecated Use OidcConfigResponse instead */
export interface AzureSsoConfig {
  enabled: boolean
  tenant_id: string
  client_id: string
  redirect_uri: string
  scopes: string
}

export interface OidcConfigResponse {
  enabled: boolean
  provider_type: 'keycloak' | 'azure' | 'custom'
  display_name: string
  discovery_url: string
  client_id: string
  client_secret: string
  redirect_uri: string
  scopes: string
}

export interface OidcDiscoveryResult {
  success: boolean
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string | null
  message?: string
}

export interface SmtpConfig {
  enabled: boolean
  host: string
  port: number
  username: string
  from: string
  tls_mode: string
}

export interface PollingConfig {
  health_poll_interval_secs: number
  patch_poll_interval_secs: number
}

export interface NotificationConfig {
  email_enabled: boolean
  email_from: string
  recipients: string[]
}

export interface SettingsResponse {
  oidc: OidcConfigResponse
  smtp: SmtpConfig
  polling: PollingConfig
  ip_whitelist: string[]
  web_tls_strategy: string
  notification: NotificationConfig
}

// ── Health Checks ────────────────────────────────────────────────────────────

export type HealthCheckType = 'service' | 'http'

export interface HealthCheck {
  id: string
  host_id: string
  name: string
  check_type: HealthCheckType
  enabled: boolean
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors: boolean
  basic_auth_user?: string
  target_host_id?: string | null
  created_at: string
  updated_at: string
}

export interface HealthCheckResult {
  id: string
  check_id: string
  healthy: boolean
  detail?: string
  latency_ms?: number
  checked_at: string
}

export interface HealthCheckWithResult extends HealthCheck {
  last_result?: HealthCheckResult
}

export interface HealthCheckListResponse {
  checks: HealthCheckWithResult[]
  total: number
}

export interface CreateHealthCheckRequest {
  name: string
  check_type: HealthCheckType
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors?: boolean
  basic_auth_user?: string
  basic_auth_pass?: string
  target_host_id?: string | null
}

export interface UpdateHealthCheckRequest {
  name?: string
  enabled?: boolean
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors?: boolean
  basic_auth_user?: string
  basic_auth_pass?: string
  target_host_id?: string | null
}

// ── Enrollment (Self-Enrollment) ─────────────────────────────────────────
export interface EnrollmentRequest {
  id: string
  machine_id: string
  fqdn: string
  ip_address: string
  os_details: Record<string, unknown>
  polling_token: string    // hashed token stored in DB
  created_at: string
  expires_at: string
}

export interface EnrollmentConflictResponse {
  error: string
  conflict: {
    existing_host: Host
    message: string
  }
}

