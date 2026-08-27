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

/// Normalize a manager URL so its host is an IP literal.
///
/// If the host is already an IP it is kept; otherwise it is resolved once here
/// (DNS works at enrollment time) and the URL is rewritten with the resolved
/// IP. This eliminates the agent's runtime DNS dependency — critical under a
/// policy set with `default deny outgoing`, where DNS (UDP/53 outbound) would
/// otherwise be blocked and the agent could never resolve the manager to pull
/// updates. Refuses an unspecified address (`0.0.0.0`/`::`) — a bind address
/// cannot be used as a connect target, and handing one to the agent is a
/// manager misconfiguration that must surface at enrollment, not silently
/// lock the host out later.
pub fn normalize_manager_url_to_ip(raw: &str) -> Result<String, String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("invalid manager URL: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!("unsupported manager URL scheme: {scheme}"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "manager URL has no host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "manager URL has no port".to_string())?;

    let ip: std::net::IpAddr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip
    } else {
        use std::net::ToSocketAddrs;
        let addrs = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| format!("failed to resolve manager hostname {host}: {e}"))?;
        addrs
            .map(|a| a.ip())
            .find(|ip| !ip.is_unspecified())
            .ok_or_else(|| format!("manager hostname {host} resolved to no usable IP"))?
    };

    if ip.is_unspecified() {
        return Err(format!(
            "manager address must be a specific IP, got {ip} — set the manager server.host to a real address, not a bind address"
        ));
    }

    // Bracket IPv6 literals in the authority component.
    let host_repr = if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    Ok(format!("{scheme}://{host_repr}:{port}"))
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

    #[test]
    fn normalize_keeps_ip_literal_and_preserves_port() {
        let n = normalize_manager_url_to_ip("https://10.0.0.5:8443").unwrap();
        assert_eq!(n, "https://10.0.0.5:8443");
    }

    #[test]
    fn normalize_brackets_ipv6() {
        let n = normalize_manager_url_to_ip("https://[::1]:8443").unwrap();
        assert_eq!(n, "https://[::1]:8443");
    }

    #[test]
    fn normalize_rejects_unspecified_address() {
        let err = normalize_manager_url_to_ip("https://0.0.0.0:8443").unwrap_err();
        assert!(err.contains("specific IP"), "got: {err}");
    }

    #[test]
    fn normalize_rejects_bad_scheme() {
        assert!(normalize_manager_url_to_ip("ftp://10.0.0.5:8443").is_err());
    }
}
