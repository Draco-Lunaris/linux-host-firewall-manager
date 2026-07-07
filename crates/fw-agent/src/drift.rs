//! Drift detection — compare current rules to last known snapshot.

use sha2::{Digest, Sha256};

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
