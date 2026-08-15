#![allow(dead_code)]
//! Drift detection — compare current rules to last known snapshot.

use sha2::{Digest, Sha256};

const EXPECTED_HASH_PATH: &str = "/var/lib/firewall-agent/expected_hash";

pub async fn check() -> anyhow::Result<()> {
    let backend = crate::backend::detect();
    match backend {
        Some(b) => {
            let snapshot = b.snapshot().await?;
            if snapshot.hash.is_empty() {
                println!("No rules currently active (empty snapshot)");
            } else {
                println!(
                    "Current snapshot hash: {} ({} rules)",
                    snapshot.hash,
                    snapshot.rules.len()
                );
            }
        }
        None => {
            println!("No firewall backend detected");
        }
    }
    Ok(())
}

/// Compute a normalized hash from a list of rule strings.
pub fn compute_hash(rules: &[String]) -> String {
    let mut hasher = Sha256::new();
    for rule in rules {
        hasher.update(rule.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// The hash of the last ruleset the agent successfully applied, persisted across
/// restarts. Each cycle the live snapshot hash is compared to this; a mismatch
/// means the rules changed out-of-band (local drift) and the agent should check
/// in early so the manager can re-apply.
pub fn load_expected_hash() -> Option<String> {
    std::fs::read_to_string(EXPECTED_HASH_PATH)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn save_expected_hash(hash: &str) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(EXPECTED_HASH_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(EXPECTED_HASH_PATH, hash)?;
    Ok(())
}
