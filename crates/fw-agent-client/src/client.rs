#![allow(clippy::redundant_closure)]
use crate::error::AgentClientError;
use crate::types::{AgentEnvelope, ApplyResult, DeployedRule};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_AGENT_PORT: u16 = 12443;

pub struct AgentClient {
    base_url: String,
    client: Client,
}

impl AgentClient {
    pub fn new(
        host_ip: &str,
        port: u16,
        client_cert_pem: &str,
        client_key_pem: &str,
        ca_cert_pem: &str,
    ) -> Result<Self, AgentClientError> {
        let identity = reqwest::Identity::from_pem(
            format!("{}\n{}", client_cert_pem, client_key_pem).as_bytes(),
        )
        .map_err(|e| AgentClientError::Http(e))?;

        let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .map_err(|e| AgentClientError::Http(e))?;

        let client = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .identity(identity)
            .add_root_certificate(ca_cert)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AgentClientError::Http(e))?;

        Ok(Self {
            base_url: format!("https://{}:{}", host_ip, port),
            client,
        })
    }

    /// Push a generic pending action to the agent (emergency push).
    /// Used by the push dispatcher for high-priority actions that can't wait for check-in.
    pub async fn push_action(&self, req: &PushActionRequest) -> Result<PushActionResponse, AgentClientError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/actions/execute", self.base_url))
            .json(req)
            .send()
            .await?
            .json::<AgentEnvelope<PushActionResponse>>()
            .await?;
        self.unwrap_envelope(resp)
    }

    /// Push rules to the agent immediately (emergency deployment).
    pub async fn deploy_rules(
        &self,
        rules: &[DeployedRule],
        job_id: &str,
    ) -> Result<ApplyResult, AgentClientError> {
        let body = serde_json::json!({
            "rules": rules,
            "job_id": job_id,
        });
        let resp = self
            .client
            .post(format!("{}/api/v1/rules/apply", self.base_url))
            .json(&body)
            .send()
            .await?
            .json::<AgentEnvelope<ApplyResult>>()
            .await?;
        self.unwrap_envelope(resp)
    }

    /// Reset all rules on the agent (emergency rollback).
    pub async fn reset_rules(&self) -> Result<(), AgentClientError> {
        let _ = self
            .client
            .post(format!("{}/api/v1/rules/reset", self.base_url))
            .send()
            .await?;
        Ok(())
    }

    /// Enable safe mode on the agent (emergency lockdown).
    pub async fn enable_safe_mode(&self) -> Result<(), AgentClientError> {
        let _ = self
            .client
            .post(format!("{}/api/v1/safe-mode/enable", self.base_url))
            .send()
            .await?;
        Ok(())
    }

    /// Disable safe mode on the agent.
    pub async fn disable_safe_mode(&self) -> Result<(), AgentClientError> {
        let _ = self
            .client
            .post(format!("{}/api/v1/safe-mode/disable", self.base_url))
            .send()
            .await?;
        Ok(())
    }

    fn unwrap_envelope<T>(&self, env: AgentEnvelope<T>) -> Result<T, AgentClientError> {
        if !env.success {
            if let Some(err) = env.error {
                return Err(AgentClientError::ApiError {
                    code: err.code,
                    message: err.message,
                });
            }
            return Err(AgentClientError::ApiError {
                code: "unknown".to_string(),
                message: "unknown error".to_string(),
            });
        }
        env.data.ok_or(AgentClientError::ApiError {
            code: "no_data".to_string(),
            message: "response had no data".to_string(),
        })
    }
}

/// Request to push a pending action to an agent.
#[derive(Debug, Serialize, Deserialize)]
pub struct PushActionRequest {
    pub action_id: uuid::Uuid,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub reason: String,
}

/// Response from the agent after executing a pushed action.
#[derive(Debug, Serialize, Deserialize)]
pub struct PushActionResponse {
    pub accepted: bool,
    pub error_message: Option<String>,
}