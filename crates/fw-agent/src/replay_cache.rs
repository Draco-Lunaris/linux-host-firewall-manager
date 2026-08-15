//! Pending-action replay cache.
//!
//! Persists the UUID of every pending action the agent has executed, so a
//! re-delivered action (e.g. the manager re-sends it because the result report
//! was lost) isn't applied twice. Stored one UUID per line at
//! /var/lib/firewall-agent/executed_actions.log.

use std::path::Path;

const PATH: &str = "/var/lib/firewall-agent/executed_actions.log";

/// Whether `action_id` has already been executed (present in the cache file).
pub fn already_executed(action_id: &str) -> bool {
    already_executed_in(PATH, action_id)
}

pub fn already_executed_in(path: &str, action_id: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.lines().any(|line| line.trim() == action_id)
}

/// Record that `action_id` has been executed (append to the cache file).
pub fn record(action_id: &str) -> anyhow::Result<()> {
    record_to(PATH, action_id)
}

pub fn record_to(path: &str, action_id: &str) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{action_id}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_detects_replays() {
        let dir = std::env::temp_dir().join(format!("fw-agent-rc-{}", uuid::Uuid::new_v4()));
        let path = dir.join("executed.log").to_string_lossy().to_string();
        let id = "11111111-1111-1111-1111-111111111111";
        assert!(!already_executed_in(&path, id));
        record_to(&path, id).unwrap();
        assert!(already_executed_in(&path, id));
        // a different id is not a replay
        assert!(!already_executed_in(
            &path,
            "22222222-2222-2222-2222-222222222222"
        ));
    }
}
