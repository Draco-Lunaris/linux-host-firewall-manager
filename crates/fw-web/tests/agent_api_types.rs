// Tests for the agent-facing API endpoints (Phase 3).
// These tests verify the request/response types and helper functions.

#[cfg(test)]
mod tests {
    use fw_web::routes::agent_api::*;
    use uuid::Uuid;

    #[test]
    fn test_check_in_request_deserialization() {
        let json = r#"{
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "rules_hash": "abc123",
            "agent_version": "0.2.0",
            "backend_type": "ufw",
            "os_info": {"os": "ubuntu"},
            "uptime_seconds": 3600,
            "config_version": 1
        }"#;
        let req: CheckInRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.rules_hash, "abc123");
        assert_eq!(req.agent_version, "0.2.0");
        assert_eq!(req.backend_type, "ufw");
        assert_eq!(req.uptime_seconds, 3600);
        assert_eq!(req.config_version, 1);
    }

    #[test]
    fn test_check_in_response_serialization() {
        let resp = CheckInResponse {
            rules_changed: true,
            rules: vec![],
            config: Some(ConfigUpdate {
                check_in_interval_secs: 900,
                push_enabled: true,
                safe_mode_enabled: false,
                backend_override: None,
                config_version: 2,
            }),
            pending_actions: vec![],
            agent_update: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"rules_changed\":true"));
        assert!(json.contains("\"check_in_interval_secs\":900"));
    }

    #[test]
    fn test_check_in_result_request_deserialization() {
        let json = r#"{
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "action_id": "660e8400-e29b-41d4-a716-446655440001",
            "success": true,
            "error_message": null,
            "new_rules_hash": "def456"
        }"#;
        let req: CheckInResultRequest = serde_json::from_str(json).unwrap();
        assert!(req.success);
        assert_eq!(req.new_rules_hash, "def456");
        assert!(req.error_message.is_none());
    }

    #[test]
    fn test_check_in_result_request_with_error() {
        let json = r#"{
            "host_id": "550e8400-e29b-41d4-a716-446655440000",
            "action_id": null,
            "success": false,
            "error_message": "Failed to apply rules: permission denied",
            "new_rules_hash": "abc123"
        }"#;
        let req: CheckInResultRequest = serde_json::from_str(json).unwrap();
        assert!(!req.success);
        assert_eq!(
            req.error_message.as_deref(),
            Some("Failed to apply rules: permission denied")
        );
        assert!(req.action_id.is_none());
    }

    #[test]
    fn test_pending_action_dto_serialization() {
        let dto = PendingActionDto {
            id: Uuid::new_v4(),
            action_type: "apply_rules".to_string(),
            payload: serde_json::json!({"policy_set_id": "test"}),
            reason: "Emergency block".to_string(),
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"action_type\":\"apply_rules\""));
        assert!(json.contains("\"reason\":\"Emergency block\""));
    }

    #[test]
    fn test_rule_dto_serialization() {
        let dto = RuleDto {
            id: Uuid::new_v4(),
            name: "Allow SSH".to_string(),
            action: "allow".to_string(),
            direction: "in".to_string(),
            protocol: "tcp".to_string(),
            src_cidr: Some("0.0.0.0/0".to_string()),
            src_port_start: None,
            src_port_end: None,
            dst_cidr: None,
            dst_port_start: Some(22),
            dst_port_end: Some(22),
            interface_in: None,
            interface_out: None,
            priority: 100,
            log: false,
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"name\":\"Allow SSH\""));
        assert!(json.contains("\"action\":\"allow\""));
        assert!(json.contains("\"dst_port_start\":22"));
    }

    #[test]
    fn test_policy_query_deserialization() {
        let json = r#"{"host_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let query: PolicyQuery = serde_json::from_str(json).unwrap();
        assert_eq!(
            query.host_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
    }

    #[test]
    fn test_config_update_serialization() {
        let config = ConfigUpdate {
            check_in_interval_secs: 300,
            push_enabled: false,
            safe_mode_enabled: true,
            backend_override: Some("firewalld".to_string()),
            config_version: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"check_in_interval_secs\":300"));
        assert!(json.contains("\"push_enabled\":false"));
        assert!(json.contains("\"safe_mode_enabled\":true"));
        assert!(json.contains("\"backend_override\":\"firewalld\""));
    }
}