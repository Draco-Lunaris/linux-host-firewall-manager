// Tests for the reworked agent client (Phase 6).

#[cfg(test)]
mod tests {
    use fw_agent_client::client::{PushActionRequest, PushActionResponse};
    use fw_agent_client::types::{AgentEnvelope, AgentError, DeployedRule, ApplyResult};
    use uuid::Uuid;

    #[test]
    fn test_push_action_request_serialization() {
        let req = PushActionRequest {
            action_id: Uuid::new_v4(),
            action_type: "apply_rules".to_string(),
            payload: serde_json::json!({"policy_set_id": "test-uuid"}),
            reason: "Emergency block 1.2.3.4".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"action_type\":\"apply_rules\""));
        assert!(json.contains("\"reason\":\"Emergency block 1.2.3.4\""));
    }

    #[test]
    fn test_push_action_response_deserialization() {
        let json = r#"{
            "accepted": true,
            "error_message": null
        }"#;
        let resp: PushActionResponse = serde_json::from_str(json).unwrap();
        assert!(resp.accepted);
        assert!(resp.error_message.is_none());
    }

    #[test]
    fn test_push_action_response_with_error() {
        let json = r#"{
            "accepted": false,
            "error_message": "Failed to apply rules: backend not active"
        }"#;
        let resp: PushActionResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.accepted);
        assert_eq!(
            resp.error_message.as_deref(),
            Some("Failed to apply rules: backend not active")
        );
    }

    #[test]
    fn test_agent_envelope_success() {
        let json = r#"{
            "success": true,
            "request_id": "req-123",
            "timestamp": "2026-07-10T00:00:00Z",
            "data": {"accepted": true, "error_message": null},
            "error": null
        }"#;
        let env: AgentEnvelope<PushActionResponse> = serde_json::from_str(json).unwrap();
        assert!(env.success);
        assert!(env.data.is_some());
        assert!(env.data.unwrap().accepted);
        assert!(env.error.is_none());
    }

    #[test]
    fn test_agent_envelope_error() {
        let json = r#"{
            "success": false,
            "request_id": "req-456",
            "timestamp": null,
            "data": null,
            "error": {
                "code": "backend_error",
                "message": "UFW not installed",
                "details": null,
                "retryable": false
            }
        }"#;
        let env: AgentEnvelope<PushActionResponse> = serde_json::from_str(json).unwrap();
        assert!(!env.success);
        assert!(env.data.is_none());
        assert!(env.error.is_some());
        assert_eq!(env.error.unwrap().code, "backend_error");
    }

    #[test]
    fn test_deployed_rule_serialization() {
        let rule = DeployedRule {
            name: "Allow SSH".to_string(),
            action: "allow".to_string(),
            direction: "in".to_string(),
            protocol: "tcp".to_string(),
            src_cidr: Some("0.0.0.0/0".to_string()),
            src_port: None,
            dst_cidr: None,
            dst_port: Some("22".to_string()),
            interface_in: None,
            interface_out: None,
            comment: Some("SSH access".to_string()),
            log: false,
            priority: 100,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"name\":\"Allow SSH\""));
        assert!(json.contains("\"action\":\"allow\""));
        assert!(json.contains("\"dst_port\":\"22\""));
    }

    #[test]
    fn test_apply_result_deserialization() {
        let json = r#"{
            "job_id": "job-123",
            "applied": 5,
            "failed": 0,
            "snapshot_hash": "abc123",
            "error": null
        }"#;
        let result: ApplyResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.job_id, "job-123");
        assert_eq!(result.applied, 5);
        assert_eq!(result.failed, 0);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_agent_error_with_retryable() {
        let json = r#"{
            "code": "timeout",
            "message": "Agent did not respond in time",
            "details": {"timeout_secs": 30},
            "retryable": true
        }"#;
        let err: AgentError = serde_json::from_str(json).unwrap();
        assert_eq!(err.code, "timeout");
        assert!(err.retryable == Some(true));
        assert!(err.details.is_some());
    }
}