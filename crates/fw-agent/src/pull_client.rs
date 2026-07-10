//! Pull client — HTTP client for the agent to call the manager's check-in endpoint.
//!
//! The agent uses this to:
//! 1. Report its current state (rules hash, version, OS info, uptime)
//! 2. Receive updated rules if the policy set changed
//! 3. Receive config updates (check-in interval, push enabled, etc.)
//! 4. Receive pending push actions that failed delivery
//! 5. Report results of applying rules or executing actions

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// HTTP client for calling the manager's agent API.
pub struct PullClient {
    manager_url: String,
    host_id: Uuid,
    client: Client,
}

#[derive(Debug, Serialize)]
pub struct CheckInRequest {
    pub host_id: Uuid,
    pub rules_hash: String,
    pub agent_version: String,
    pub backend_type: String,
    pub os_info: serde_json::Value,
    pub uptime_seconds: i64,
    pub config_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct CheckInResponse {
    pub rules_changed: bool,
    pub rules: Vec<RuleDto>,
    pub config: Option<ConfigUpdate>,
    pub pending_actions: Vec<PendingActionDto>,
    pub agent_update: Option<AgentUpdateInfo>,
}

#[derive(Debug, Deserialize)]
pub struct RuleDto {
    pub id: Uuid,
    pub name: String,
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_cidr: Option<String>,
    pub src_port_start: Option<i32>,
    pub src_port_end: Option<i32>,
    pub dst_cidr: Option<String>,
    pub dst_port_start: Option<i32>,
    pub dst_port_end: Option<i32>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub priority: i32,
    pub log: bool,
}

#[derive(Debug, Deserialize)]
pub struct ConfigUpdate {
    pub check_in_interval_secs: i32,
    pub push_enabled: bool,
    pub safe_mode_enabled: bool,
    pub backend_override: Option<String>,
    pub config_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct PendingActionDto {
    pub id: Uuid,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentUpdateInfo {
    pub latest_version: String,
    pub download_url: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckInResultRequest {
    pub host_id: Uuid,
    pub action_id: Option<Uuid>,
    pub success: bool,
    pub error_message: Option<String>,
    pub new_rules_hash: String,
}

impl PullClient {
    /// Create a new pull client.
    ///
    /// # Arguments
    /// * `manager_url` - Base URL of the manager (e.g., "https://manager.moon-dragon.us")
    /// * `host_id` - UUID of this agent's host record
    /// * `client_cert_pem` - PEM-encoded mTLS client certificate
    /// * `client_key_pem` - PEM-encoded mTLS private key
    /// * `ca_cert_pem` - PEM-encoded CA certificate for server verification
    pub fn new(
        manager_url: &str,
        host_id: Uuid,
        client_cert_pem: &str,
        client_key_pem: &str,
        ca_cert_pem: &str,
    ) -> Result<Self> {
        let identity = reqwest::Identity::from_pem(
            format!("{}\n{}", client_cert_pem, client_key_pem).as_bytes(),
        )
        .context("Failed to create mTLS identity")?;

        let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .context("Failed to parse CA certificate")?;

        let client = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .identity(identity)
            .add_root_certificate(ca_cert)
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            manager_url: manager_url.trim_end_matches('/').to_string(),
            host_id,
            client,
        })
    }

    /// Call the manager's check-in endpoint.
    pub async fn check_in(&self, req: &CheckInRequest) -> Result<CheckInResponse> {
        let url = format!("{}/api/v1/agent/check-in", self.manager_url);
        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .context("Failed to send check-in request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Check-in failed: {} - {}", status, body);
        }

        resp.json::<CheckInResponse>()
            .await
            .context("Failed to parse check-in response")
    }

    /// Report the result of applying rules or executing a pending action.
    pub async fn report_result(&self, req: &CheckInResultRequest) -> Result<()> {
        let url = format!("{}/api/v1/agent/check-in/result", self.manager_url);
        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .context("Failed to send result report")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Result report failed: {} - {}", status, body);
        }

        Ok(())
    }

    /// Fetch the current policy set rules for this host (read-only, no check-in side effects).
    pub async fn fetch_policy(&self) -> Result<Vec<RuleDto>> {
        let url = format!(
            "{}/api/v1/agent/policy?host_id={}",
            self.manager_url, self.host_id
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch policy")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Policy fetch failed: {} - {}", status, body);
        }

        resp.json::<Vec<RuleDto>>()
            .await
            .context("Failed to parse policy response")
    }
}