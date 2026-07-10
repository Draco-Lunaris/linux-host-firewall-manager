// Tests for the new pull-model types (Phase 1).

#[cfg(test)]
mod tests {
    use crate::models::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_pending_action_type_enum_values() {
        // Verify the enum variants match the DB ENUM order.
        let variants = [
            PendingActionType::ApplyRules,
            PendingActionType::Rollback,
            PendingActionType::SafeModeOn,
            PendingActionType::SafeModeOff,
            PendingActionType::ReloadConfig,
            PendingActionType::AgentUpgrade,
        ];
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn test_pending_action_status_enum_values() {
        let variants = [
            PendingActionStatus::Queued,
            PendingActionStatus::Pushing,
            PendingActionStatus::Delivered,
            PendingActionStatus::Executed,
            PendingActionStatus::Failed,
            PendingActionStatus::Expired,
        ];
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn test_agent_check_in_construction() {
        let check_in = AgentCheckIn {
            id: Uuid::new_v4(),
            host_id: Uuid::new_v4(),
            rules_hash: "abc123".to_string(),
            agent_version: "0.2.0".to_string(),
            backend_type: "ufw".to_string(),
            os_info: serde_json::json!({"os": "ubuntu", "version": "24.04"}),
            uptime_seconds: 3600,
            config_version: 1,
            pending_results: serde_json::json!([]),
            checked_in_at: Utc::now(),
        };
        assert_eq!(check_in.rules_hash, "abc123");
        assert_eq!(check_in.agent_version, "0.2.0");
        assert_eq!(check_in.backend_type, "ufw");
        assert_eq!(check_in.uptime_seconds, 3600);
    }

    #[test]
    fn test_host_config_override_defaults() {
        let override_cfg = HostConfigOverride {
            host_id: Uuid::new_v4(),
            check_in_interval_secs: 900,
            push_enabled: true,
            safe_mode_enabled: false,
            backend_override: None,
            config_version: 1,
            updated_at: Utc::now(),
        };
        assert_eq!(override_cfg.check_in_interval_secs, 900);
        assert!(override_cfg.push_enabled);
        assert!(!override_cfg.safe_mode_enabled);
        assert!(override_cfg.backend_override.is_none());
    }

    #[test]
    fn test_pending_action_construction() {
        let action = PendingAction {
            id: Uuid::new_v4(),
            host_id: Uuid::new_v4(),
            action_type: PendingActionType::ApplyRules,
            payload: serde_json::json!({"policy_set_id": "test"}),
            reason: "Emergency block".to_string(),
            priority: 10,
            status: PendingActionStatus::Queued,
            attempts: 0,
            max_attempts: 3,
            created_at: Utc::now(),
            first_attempt_at: None,
            delivered_at: None,
            executed_at: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };
        assert_eq!(action.priority, 10);
        assert_eq!(action.status, PendingActionStatus::Queued);
        assert_eq!(action.max_attempts, 3);
    }

    #[test]
    fn test_pending_action_type_serialization() {
        // Verify snake_case serialization matches DB ENUM values.
        let json = serde_json::to_string(&PendingActionType::ApplyRules).unwrap();
        assert_eq!(json, "\"apply_rules\"");

        let json = serde_json::to_string(&PendingActionType::SafeModeOn).unwrap();
        assert_eq!(json, "\"safe_mode_on\"");

        let json = serde_json::to_string(&PendingActionType::AgentUpgrade).unwrap();
        assert_eq!(json, "\"agent_upgrade\"");
    }

    #[test]
    fn test_pending_action_status_serialization() {
        let json = serde_json::to_string(&PendingActionStatus::Queued).unwrap();
        assert_eq!(json, "\"queued\"");

        let json = serde_json::to_string(&PendingActionStatus::Delivered).unwrap();
        assert_eq!(json, "\"delivered\"");
    }
}