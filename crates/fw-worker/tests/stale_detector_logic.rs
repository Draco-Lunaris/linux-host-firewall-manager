// Tests for the stale agent detector and push dispatcher (Phase 4).
// These tests verify the staleness calculation logic without a real database.

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    /// Calculate the health status based on last check-in time and interval.
    /// This mirrors the logic in stale_agent_detector::detect_stale_agents.
    fn calculate_status(
        last_check_in: Option<DateTime<Utc>>,
        interval_secs: i64,
        now: DateTime<Utc>,
    ) -> &'static str {
        let stale_2x = interval_secs * 2;
        let stale_4x = interval_secs * 4;

        match last_check_in {
            Some(last) => {
                let elapsed = (now - last).num_seconds();
                if elapsed > stale_4x {
                    "unreachable"
                } else if elapsed > stale_2x {
                    "degraded"
                } else {
                    "healthy"
                }
            }
            None => "pending",
        }
    }

    #[test]
    fn test_status_healthy_within_2x_interval() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(100);
        assert_eq!(calculate_status(Some(last), 900, now), "healthy");
    }

    #[test]
    fn test_status_degraded_between_2x_and_4x() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(2000); // > 2x900=1800
        assert_eq!(calculate_status(Some(last), 900, now), "degraded");
    }

    #[test]
    fn test_status_unreachable_beyond_4x() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(4000); // > 4x900=3600
        assert_eq!(calculate_status(Some(last), 900, now), "unreachable");
    }

    #[test]
    fn test_status_pending_never_checked_in() {
        let now = Utc::now();
        assert_eq!(calculate_status(None, 900, now), "pending");
    }

    #[test]
    fn test_status_healthy_with_custom_interval() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(50);
        assert_eq!(calculate_status(Some(last), 60, now), "healthy"); // < 2x60=120
    }

    #[test]
    fn test_status_degraded_with_custom_interval() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(150);
        assert_eq!(calculate_status(Some(last), 60, now), "degraded"); // > 2x60=120, < 4x60=240
    }

    #[test]
    fn test_status_unreachable_with_custom_interval() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(300);
        assert_eq!(calculate_status(Some(last), 60, now), "unreachable"); // > 4x60=240
    }

    #[test]
    fn test_status_healthy_at_exact_2x_boundary() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(1800);
        // elapsed = 1800, stale_2x = 1800 — NOT > 1800, so healthy
        assert_eq!(calculate_status(Some(last), 900, now), "healthy");
    }

    #[test]
    fn test_status_degraded_just_past_2x() {
        let now = Utc::now();
        let last = now - chrono::Duration::seconds(1801);
        assert_eq!(calculate_status(Some(last), 900, now), "degraded");
    }
}