//! Safe mode (SEC-006).
//!
//! If the agent cannot reach the manager for N minutes (configurable,
//! default 30), it reverts to the last-known-good ruleset snapshot
//! and raises a local alert. This is opt-in per host.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

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

    pub fn is_active(&self) -> bool {
        self.safe_mode_active.load(Ordering::Relaxed)
    }
}
