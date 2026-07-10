// Tests for the pull client and pull loop (Phase 2).

#[cfg(test)]
mod tests {
    use fw_agent::pull_client::*;
    use uuid::Uuid;

    #[test]
    fn test_check_in_request_serialization() {
        let req = CheckInRequest {
            host_id: Uuid::new_v4(),
            rules_hash: "abc123".to_string(),
            agent_version: "0.2.0".to_string(),
            backend_type: "ufw".to_string(),
            os_info: serde_json::json!({"os": "ubuntu"}),
            uptime_seconds: 3600,
            config_version: 1,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"rules_hash\":\"abc123\""));
        assert!(json.contains("\"backend_type\":\"ufw\""));
        assert!(json.contains("\"uptime_seconds\":3600"));
    }

    #[test]
    fn test_check_in_response_deserialization() {
        let json = r#"{
            "rules_changed": true,
            "rules": [{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Allow SSH",
                "action": "allow",
                "direction": "in",
                "protocol": "tcp",
                "src_cidr": "0.0.0.0/0",
                "src_port_start": null,
                "src_port_end": null,
                "dst_cidr": null,
                "dst_port_start": 22,
                "dst_port_end": 22,
                "interface_in": null,
                "interface_out": null,
                "priority": 100,
                "log": false
            }],
            "config": {
                "check_in_interval_secs": 300,
                "push_enabled": true,
                "safe_mode_enabled": false,
                "backend_override": null,
                "config_version": 2
            },
            "pending_actions": [{
                "id": "660e8400-e29b-41d4-a716-446655440001",
                "action_type": "safe_mode_on",
                "payload": {},
                "reason": "Emergency"
            }],
            "agent_update": null
        }"#;
        let resp: CheckInResponse = serde_json::from_str(json).unwrap();
        assert!(resp.rules_changed);
        assert_eq!(resp.rules.len(), 1);
        assert_eq!(resp.rules[0].name, "Allow SSH");
        assert_eq!(resp.rules[0].dst_port_start, Some(22));
        assert!(resp.config.is_some());
        assert_eq!(resp.config.as_ref().unwrap().check_in_interval_secs, 300);
        assert_eq!(resp.pending_actions.len(), 1);
        assert_eq!(resp.pending_actions[0].action_type, "safe_mode_on");
        assert!(resp.agent_update.is_none());
    }

    #[test]
    fn test_check_in_result_request_serialization() {
        let req = CheckInResultRequest {
            host_id: Uuid::new_v4(),
            action_id: Some(Uuid::new_v4()),
            success: true,
            error_message: None,
            new_rules_hash: "def456".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"new_rules_hash\":\"def456\""));
    }

    #[test]
    fn test_check_in_response_empty_rules() {
        let json = r#"{
            "rules_changed": false,
            "rules": [],
            "config": null,
            "pending_actions": [],
            "agent_update": null
        }"#;
        let resp: CheckInResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.rules_changed);
        assert!(resp.rules.is_empty());
        assert!(resp.config.is_none());
        assert!(resp.pending_actions.is_empty());
    }

    #[test]
    fn test_rule_dto_all_fields() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Block bad actor",
            "action": "deny",
            "direction": "in",
            "protocol": "any",
            "src_cidr": "10.0.0.0/8",
            "src_port_start": null,
            "src_port_end": null,
            "dst_cidr": null,
            "dst_port_start": null,
            "dst_port_end": null,
            "interface_in": "eth0",
            "interface_out": null,
            "priority": 50,
            "log": true
        }"#;
        let rule: RuleDto = serde_json::from_str(json).unwrap();
        assert_eq!(rule.name, "Block bad actor");
        assert_eq!(rule.action, "deny");
        assert_eq!(rule.src_cidr, Some("10.0.0.0/8".to_string()));
        assert_eq!(rule.interface_in, Some("eth0".to_string()));
        assert_eq!(rule.priority, 50);
        assert!(rule.log);
    }

    #[test]
    fn test_agent_update_info_deserialization() {
        let json = r#"{
            "latest_version": "0.3.0",
            "download_url": "https://manager/repo/agent-0.3.0.deb",
            "checksum": "sha256:abc123"
        }"#;
        let info: AgentUpdateInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.latest_version, "0.3.0");
        assert!(info.download_url.contains("agent-0.3.0.deb"));
        assert!(info.checksum.is_some());
    }
}