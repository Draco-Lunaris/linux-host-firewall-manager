#![allow(clippy::redundant_closure)]
use crate::error::AgentClientError;
use crate::types::{AgentEnvelope, ApplyResult, HealthResponse, RuleSnapshot, SystemInfo};
use reqwest::Client;
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

    pub async fn health(&self) -> Result<HealthResponse, AgentClientError> {
        let resp = self
            .client
            .get(format!("{}/api/v1/health", self.base_url))
            .send()
            .await?
            .json::<AgentEnvelope<HealthResponse>>()
            .await?;
        self.unwrap_envelope(resp)
    }

    pub async fn system_info(&self) -> Result<SystemInfo, AgentClientError> {
        let resp = self
            .client
            .get(format!("{}/api/v1/system/info", self.base_url))
            .send()
            .await?
            .json::<AgentEnvelope<SystemInfo>>()
            .await?;
        self.unwrap_envelope(resp)
    }

    pub async fn get_snapshot(&self) -> Result<RuleSnapshot, AgentClientError> {
        let resp = self
            .client
            .get(format!("{}/api/v1/rules/snapshot", self.base_url))
            .send()
            .await?
            .json::<AgentEnvelope<RuleSnapshot>>()
            .await?;
        self.unwrap_envelope(resp)
    }

    pub async fn deploy_rules(
        &self,
        rules: &[crate::types::DeployedRule],
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

    pub async fn reset_rules(&self) -> Result<(), AgentClientError> {
        let _ = self
            .client
            .post(format!("{}/api/v1/rules/reset", self.base_url))
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
