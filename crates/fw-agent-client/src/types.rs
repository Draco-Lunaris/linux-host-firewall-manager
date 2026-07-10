use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnvelope<T> {
    pub success: bool,
    pub request_id: Option<String>,
    pub timestamp: Option<String>,
    pub data: Option<T>,
    pub error: Option<AgentError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub retryable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedRule {
    pub name: String,
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_cidr: Option<String>,
    pub src_port: Option<String>,
    pub dst_cidr: Option<String>,
    pub dst_port: Option<String>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    pub log: bool,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub job_id: String,
    pub applied: u32,
    pub failed: u32,
    pub snapshot_hash: String,
    pub error: Option<String>,
}