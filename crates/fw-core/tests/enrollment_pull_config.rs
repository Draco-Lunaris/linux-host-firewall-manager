// Tests for the enrollment pull config extension (Phase 5).

#[cfg(test)]
mod tests {
    use fw_core::models::{PkiBundle, PullConfigBundle};

    #[test]
    fn test_pki_bundle_with_pull_config_serialization() {
        let bundle = PkiBundle {
            ca_chain: vec![
                "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            ],
            server_cert: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            crl_pem: None,
            pull_config: Some(PullConfigBundle {
                check_in_interval_secs: 900,
                push_enabled: true,
                config_version: 1,
                manager_agent_url: "https://manager:8443".to_string(),
            }),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("\"check_in_interval_secs\":900"));
        assert!(json.contains("\"push_enabled\":true"));
        assert!(json.contains("\"manager_agent_url\""));
    }

    #[test]
    fn test_pki_bundle_without_pull_config() {
        let bundle = PkiBundle {
            ca_chain: vec!["ca".to_string()],
            server_cert: "cert".to_string(),
            crl_pem: None,
            pull_config: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        // pull_config should be null when not present
        assert!(json.contains("\"pull_config\":null"));
    }

    #[test]
    fn test_pki_bundle_with_pull_config_deserialization() {
        let json = r#"{
            "ca_chain": ["ca"],
            "server_cert": "cert",
            "crl_pem": null,
            "pull_config": {
                "check_in_interval_secs": 300,
                "push_enabled": false,
                "config_version": 2,
                "manager_agent_url": "https://fwm:8443"
            }
        }"#;
        let bundle: PkiBundle = serde_json::from_str(json).unwrap();
        assert!(bundle.pull_config.is_some());
        let pc = bundle.pull_config.unwrap();
        assert_eq!(pc.check_in_interval_secs, 300);
        assert!(!pc.push_enabled);
        assert_eq!(pc.config_version, 2);
    }
}
