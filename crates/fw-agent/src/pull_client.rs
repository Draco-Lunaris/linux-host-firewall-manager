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
#[derive(Clone)]
pub struct PullClient {
    manager_url: String,
    host_id: Uuid,
    client: Client,
    /// A client with no request timeout for the long-lived SSE events stream
    /// (the regular `client` has a 30s timeout that would cut the stream short).
    stream_client: Client,
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
    /// SHA-256 of the agent binary (current_exe), sent on check-in for
    /// integrity tracking (SEC-007 stub — real GPG verification is a follow-up;
    /// the manager currently ignores this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_binary_hash: Option<String>,
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

        // Separate client for the long-lived SSE events stream: no request
        // timeout (the stream is held up to check_in_interval - 30s).
        let stream_identity = reqwest::Identity::from_pem(
            format!("{}\n{}", client_cert_pem, client_key_pem).as_bytes(),
        )
        .context("Failed to create mTLS identity")?;
        let stream_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .context("Failed to parse CA certificate")?;
        let stream_client = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .identity(stream_identity)
            .add_root_certificate(stream_ca)
            .build()
            .context("Failed to build streaming HTTP client")?;

        Ok(Self {
            manager_url: manager_url.trim_end_matches('/').to_string(),
            host_id,
            client,
            stream_client,
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

    /// Open the manager's SSE events stream and drive `notify` on each
    /// `check-in` event, and once when the stream ends (hold-window timeout or
    /// connection drop) so the caller runs a normal cycle. Returns when the
    /// stream closes or errors. Uses `stream_client` (no timeout) and reads
    /// incrementally via `chunk()` so no reqwest `stream` feature is required.
    pub async fn run_events_stream(
        &self,
        notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/agent/events", self.manager_url);
        let resp = self
            .stream_client
            .get(&url)
            .send()
            .await
            .context("Failed to open SSE events stream")?;
        let mut resp = resp
            .error_for_status()
            .context("SSE events stream rejected")?;

        let mut buf = String::new();
        loop {
            match resp.chunk().await.context("Failed to read SSE chunk")? {
                Some(chunk) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    // SSE frames are separated by a blank line (\n\n). Process
                    // every complete frame currently buffered.
                    while let Some(idx) = buf.find("\n\n") {
                        let frame = buf[..idx].to_string();
                        buf.drain(..idx + 2);
                        if let Some(event) = parse_sse_event(&frame) {
                            if event == "check-in" {
                                notify.notify_one();
                            }
                            // other events (e.g. `timeout`, keepalive comments)
                            // are not force signals — the stream end below
                            // handles the hold-window timeout.
                        }
                    }
                }
                None => {
                    // Stream ended (server closed at the hold window, or the
                    // connection dropped). Run a normal cycle either way.
                    notify.notify_one();
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Parse the `event:` field out of a single SSE frame. Returns `None` for
/// comment-only frames (keepalive lines starting with `:`).
fn parse_sse_event(frame: &str) -> Option<String> {
    let mut event: Option<String> = None;
    for line in frame.lines() {
        if line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event = Some(rest.trim().to_string());
        }
    }
    event
}

#[cfg(test)]
mod tests {
    use super::parse_sse_event;

    #[test]
    fn parses_check_in_event() {
        assert_eq!(
            parse_sse_event("event:check-in\ndata:now").as_deref(),
            Some("check-in")
        );
    }

    #[test]
    fn parses_timeout_event() {
        assert_eq!(
            parse_sse_event("event:timeout\ndata:hold-expired").as_deref(),
            Some("timeout")
        );
    }

    #[test]
    fn ignores_keepalive_comments() {
        assert_eq!(parse_sse_event(": keepalive 1234"), None);
    }
}
