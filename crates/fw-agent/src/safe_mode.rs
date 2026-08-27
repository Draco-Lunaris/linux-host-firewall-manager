//! Safe mode (SEC-006).
//!
//! If the agent cannot reach the manager for N minutes (configurable,
//! default 30), it reverts to the last-known-good ruleset snapshot
//! and raises a local alert. This is opt-in per host.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use fw_core::models::FirewallRule;

const LAST_GOOD_PATH: &str = "/var/lib/firewall-agent/last_good.rules.json";

pub struct SafeModeState {
    pub last_manager_contact: Arc<std::sync::Mutex<Option<Instant>>>,
    pub safe_mode_active: Arc<AtomicBool>,
    pub timeout_secs: u64,
}

impl SafeModeState {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            last_manager_contact: Arc::new(std::sync::Mutex::new(Some(Instant::now()))),
            safe_mode_active: Arc::new(AtomicBool::new(false)),
            timeout_secs,
        }
    }

    pub fn record_manager_contact(&self) {
        *self.last_manager_contact.lock().unwrap() = Some(Instant::now());
        self.safe_mode_active.store(false, Ordering::Relaxed);
    }

    pub fn check(&self) -> bool {
        let elapsed = {
            let last = self.last_manager_contact.lock().unwrap();
            match *last {
                Some(t) => t.elapsed().as_secs(),
                None => 0,
            }
        };

        if elapsed > self.timeout_secs {
            if !self.safe_mode_active.load(Ordering::Relaxed) {
                tracing::warn!(
                    elapsed_secs = elapsed,
                    timeout_secs = self.timeout_secs,
                    "Manager unreachable for {}s — entering safe mode",
                    elapsed
                );
                self.safe_mode_active.store(true, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }
}

/// Persist the last-known-good ruleset (the one most recently applied
/// successfully) so safe mode can revert to it if the manager becomes
/// unreachable. Stored as JSON at /var/lib/firewall-agent/last_good.rules.json.
pub fn save_last_good(rules: &[FirewallRule]) -> anyhow::Result<()> {
    save_last_good_to(LAST_GOOD_PATH, rules)
}

pub fn save_last_good_to(path: &str, rules: &[FirewallRule]) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(rules)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load the last-known-good ruleset, if one was persisted.
pub fn load_last_good() -> anyhow::Result<Vec<FirewallRule>> {
    load_last_good_from(LAST_GOOD_PATH)
}

pub fn load_last_good_from(path: &str) -> anyhow::Result<Vec<FirewallRule>> {
    let json = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

// ── Last-applied default policies ──────────────────────────────────────────
// Mirrors last_good: the agent caches the policy-set default policies it last
// applied so it can (a) detect a defaults-only change and trigger an apply, and
// (b) re-apply the same defaults during a local-drift self-heal. Stored as
// JSON at /var/lib/firewall-agent/last_defaults.json. None = system default.

const LAST_DEFAULTS_PATH: &str = "/var/lib/firewall-agent/last_defaults.json";

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct LastDefaults {
    pub default_input_policy: Option<String>,
    pub default_output_policy: Option<String>,
}

pub fn save_last_defaults(defaults: &LastDefaults) -> anyhow::Result<()> {
    save_last_defaults_to(LAST_DEFAULTS_PATH, defaults)
}

pub fn save_last_defaults_to(path: &str, defaults: &LastDefaults) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(defaults)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_last_defaults() -> Option<LastDefaults> {
    load_last_defaults_from(LAST_DEFAULTS_PATH)
}

pub fn load_last_defaults_from(path: &str) -> Option<LastDefaults> {
    let json = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol};
    use uuid::Uuid;

    fn rule(name: &str) -> FirewallRule {
        FirewallRule {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: String::new(),
            action: FirewallAction::Allow,
            direction: FirewallDirection::In,
            protocol: FirewallProtocol::Tcp,
            src_cidr: None,
            src_port_start: None,
            src_port_end: None,
            dst_cidr: Some("10.0.0.0/8".to_string()),
            dst_port_start: Some(22),
            dst_port_end: Some(22),
            interface_in: None,
            interface_out: None,
            comment: String::new(),
            log: false,
            priority: 100,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn last_good_round_trips_through_json() {
        let dir = std::env::temp_dir().join(format!("fw-agent-lg-{}", Uuid::new_v4()));
        let path = dir
            .join("last_good.rules.json")
            .to_string_lossy()
            .to_string();
        let rules = vec![rule("ssh"), rule("web")];
        save_last_good_to(&path, &rules).unwrap();
        let loaded = load_last_good_from(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "ssh");
        assert_eq!(loaded[1].dst_port_start, Some(22));
    }

    #[test]
    fn last_defaults_round_trips_and_defaults_when_absent() {
        let dir = std::env::temp_dir().join(format!("fw-agent-ld-{}", Uuid::new_v4()));
        let path = dir.join("last_defaults.json").to_string_lossy().to_string();
        let d = super::LastDefaults {
            default_input_policy: Some("deny".to_string()),
            default_output_policy: Some("deny".to_string()),
        };
        save_last_defaults_to(&path, &d).unwrap();
        let loaded = load_last_defaults_from(&path).unwrap();
        assert_eq!(loaded.default_input_policy.as_deref(), Some("deny"));
        assert_eq!(loaded.default_output_policy.as_deref(), Some("deny"));

        // Absent file → None (Default).
        let missing = dir.join("nope.json").to_string_lossy().to_string();
        assert!(load_last_defaults_from(&missing).is_none());
    }
}
