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
        if rule.action != FirewallAction::Deny && rule.action != FirewallAction::Reject {
            continue;
        }

        if let Some(src) = &rule.src_cidr {
            let rule_net = match src.parse::<IpNet>() {
                Ok(n) => n,
                Err(_) => continue,
            };

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
                    violations.push(format!(
                        "Rule '{}' would block protected CIDR {} ({})",
                        rule.name,
                        protected,
                        rule.action.as_str()
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

/// Get the manager's IP from the config URL to auto-add it as a protected CIDR.
pub fn auto_detect_manager_cidr(manager_url: &str) -> Option<String> {
    let parsed = url::Url::parse(manager_url).ok()?;
    let host = parsed.host_str()?;
    // Resolve hostname to IP
    use std::net::ToSocketAddrs;
    let addrs = format!("{}:443", host).to_socket_addrs().ok()?;
    for addr in addrs {
        return Some(addr.ip().to_string());
    }
    None
}
