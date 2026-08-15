#![allow(dead_code)]
//! Protected CIDR enforcement (SEC-006).
//!
//! The agent rejects any rule that would block a protected CIDR
//! (e.g., the manager's IP, the management interface subnet).
//! This prevents management-interface lockout.

use fw_core::models::{FirewallAction, FirewallRule};
use ipnet::IpNet;

pub fn check_rules_against_protected(
    rules: &[FirewallRule],
    protected_cidrs: &[String],
) -> Result<(), Vec<String>> {
    if protected_cidrs.is_empty() {
        return Ok(());
    }

    let mut violations = Vec::new();

    for rule in rules {
        // (1) A deny/reject rule whose source covers a protected CIDR would
        // block management traffic to that CIDR.
        if matches!(rule.action, FirewallAction::Deny | FirewallAction::Reject) {
            if let Some(src) = &rule.src_cidr {
                if let Some(p) = overlaps_protected(src, protected_cidrs) {
                    violations.push(format!(
                        "Rule '{}' would block protected CIDR {} ({})",
                        rule.name,
                        p,
                        rule.action.as_str()
                    ));
                }
            }
        }

        // (2) An allow rule from a broad source to a protected destination
        // would expose a protected service to the world.
        if matches!(rule.action, FirewallAction::Allow) && is_broad_src(rule.src_cidr.as_deref()) {
            if let Some(dst) = &rule.dst_cidr {
                if let Some(p) = overlaps_protected(dst, protected_cidrs) {
                    violations.push(format!(
                        "Rule '{}' allows broad traffic to protected CIDR {}",
                        rule.name, p
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Whether `cidr` overlaps any protected CIDR (same IP family, one contains
/// the other's network address). Returns the matching protected CIDR if so.
fn overlaps_protected(cidr: &str, protected_cidrs: &[String]) -> Option<String> {
    let rule_net = cidr.parse::<IpNet>().ok()?;
    for protected in protected_cidrs {
        let protected_net = match protected.parse::<IpNet>() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if rule_net.network().is_ipv4() != protected_net.network().is_ipv4() {
            continue;
        }
        if rule_net.contains(&protected_net.network())
            || protected_net.contains(&rule_net.network())
        {
            return Some(protected.clone());
        }
    }
    None
}

/// A "broad" source matches every address: no CIDR, or the unspecified network
/// (0.0.0.0/0, ::/0, or bare 0.0.0.0 / ::).
fn is_broad_src(src: Option<&str>) -> bool {
    match src {
        None => true,
        Some(s) => {
            let t = s.trim();
            t.is_empty() || t == "0.0.0.0/0" || t == "::/0" || t == "0.0.0.0" || t == "::"
        }
    }
}

/// Get the manager's IP from the config URL to auto-add it as a protected CIDR.
pub fn auto_detect_manager_cidr(manager_url: &str) -> Option<String> {
    let parsed = url::Url::parse(manager_url).ok()?;
    let host = parsed.host_str()?;
    // Resolve hostname to IP
    use std::net::ToSocketAddrs;
    let mut addrs = format!("{}:443", host).to_socket_addrs().ok()?;
    addrs.next().map(|addr| addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
    use uuid::Uuid;

    fn make_rule(action: FirewallAction, src: Option<&str>, dst: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            description: String::new(),
            action,
            direction: FirewallDirection::In,
            protocol: FirewallProtocol::Any,
            src_cidr: src.map(|s| s.to_string()),
            src_port_start: None,
            src_port_end: None,
            dst_cidr: dst.map(|s| s.to_string()),
            dst_port_start: None,
            dst_port_end: None,
            interface_in: None,
            interface_out: None,
            comment: String::new(),
            log: false,
            priority: 0,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn no_protected_cidrs_is_ok() {
        let rules = vec![make_rule(FirewallAction::Deny, Some("10.0.0.0/8"), None)];
        assert!(check_rules_against_protected(&rules, &[]).is_ok());
    }

    #[test]
    fn deny_covering_protected_src_is_flagged() {
        let rules = vec![make_rule(FirewallAction::Deny, Some("10.0.0.0/8"), None)];
        let res = check_rules_against_protected(&rules, &["10.1.2.3/32".to_string()]);
        assert!(res.is_err());
        assert!(res.unwrap_err()[0].contains("block protected CIDR"));
    }

    #[test]
    fn broad_allow_to_protected_dst_is_flagged() {
        let rules = vec![make_rule(FirewallAction::Allow, None, Some("10.1.2.3/32"))];
        let res = check_rules_against_protected(&rules, &["10.1.2.3/32".to_string()]);
        assert!(res.is_err());
        assert!(res.unwrap_err()[0].contains("broad traffic to protected CIDR"));
    }

    #[test]
    fn narrow_allow_to_protected_dst_is_allowed() {
        // A narrow source (specific host) to a protected dst is not a broad exposure.
        let rules = vec![make_rule(
            FirewallAction::Allow,
            Some("192.168.1.5/32"),
            Some("10.1.2.3/32"),
        )];
        let res = check_rules_against_protected(&rules, &["10.1.2.3/32".to_string()]);
        assert!(res.is_ok());
    }

    #[test]
    fn broad_allow_to_unprotected_dst_is_allowed() {
        let rules = vec![make_rule(FirewallAction::Allow, None, Some("8.8.8.8/32"))];
        let res = check_rules_against_protected(&rules, &["10.1.2.3/32".to_string()]);
        assert!(res.is_ok());
    }
}
