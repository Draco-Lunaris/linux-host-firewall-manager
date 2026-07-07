#![allow(dead_code)]
//! Rule compiler — converts typed FirewallRule to backend-specific command strings.

use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};

/// Compile a single rule to a UFW command string.
pub fn compile_ufw(rule: &FirewallRule) -> String {
    let mut cmd = "ufw".to_string();
    match rule.action {
        FirewallAction::Allow => cmd.push_str(" allow"),
        FirewallAction::Deny => cmd.push_str(" deny"),
        FirewallAction::Reject => cmd.push_str(" reject"),
        FirewallAction::Limit => cmd.push_str(" limit"),
        FirewallAction::Masquerade => cmd.push_str(" masquerade"),
    }
    if rule.direction == FirewallDirection::Out {
        cmd.push_str(" out");
    }
    if rule.protocol != FirewallProtocol::Any {
        cmd.push_str(&format!(
            " proto {}",
            format!("{:?}", &rule.protocol).to_lowercase()
        ));
    }
    if let Some(src) = &rule.src_cidr {
        cmd.push_str(&format!(" from {}", src));
    }
    if let Some(dst) = &rule.dst_cidr {
        cmd.push_str(&format!(" to {}", dst));
    }
    if let Some(port) = rule.dst_port_start {
        if let Some(end) = rule.dst_port_end {
            if port == end {
                cmd.push_str(&format!(" port {}", port));
            } else {
                cmd.push_str(&format!(" port {}:{}", port, end));
            }
        } else {
            cmd.push_str(&format!(" port {}", port));
        }
    }
    if !rule.comment.is_empty() {
        cmd.push_str(&format!(" comment '{}'", rule.comment.replace('\'', "")));
    }
    cmd
}

/// Compile a single rule to a firewalld rich-rule command string.
pub fn compile_firewalld(rule: &FirewallRule) -> String {
    let action = match rule.action {
        FirewallAction::Allow => "accept",
        FirewallAction::Deny => "drop",
        FirewallAction::Reject => "reject",
        FirewallAction::Limit => "accept",
        FirewallAction::Masquerade => "masquerade",
    };
    let proto = match &rule.protocol {
        FirewallProtocol::Any => "all".to_string(),
        p => format!("{:?}", p).to_lowercase(),
    };
    let src = rule.src_cidr.as_deref().unwrap_or("0.0.0.0/0");
    let port = rule
        .dst_port_start
        .map(|p| p.to_string())
        .unwrap_or_default();

    if port.is_empty() {
        format!(
            "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"{}\" {}'",
            src, action
        )
    } else {
        format!(
            "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"{}\" port port=\"{}\" protocol=\"{}\" {}'",
            src, port, proto, action
        )
    }
}

/// Compile a list of rules to backend-specific commands.
pub fn compile_all(rules: &[FirewallRule], backend: &str) -> Vec<String> {
    match backend {
        "ufw" => rules.iter().map(compile_ufw).collect(),
        "firewalld" => rules.iter().map(compile_firewalld).collect(),
        _ => rules.iter().map(compile_ufw).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_rule(
        action: FirewallAction,
        proto: FirewallProtocol,
        src: Option<&str>,
        port: Option<i32>,
    ) -> FirewallRule {
        FirewallRule {
            id: Uuid::nil(),
            name: "test".to_string(),
            description: String::new(),
            action,
            direction: FirewallDirection::In,
            protocol: proto,
            src_cidr: src.map(|s| s.to_string()),
            src_port_start: None,
            src_port_end: None,
            dst_cidr: None,
            dst_port_start: port,
            dst_port_end: port,
            interface_in: None,
            interface_out: None,
            comment: "test rule".to_string(),
            log: false,
            priority: 100,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_compile_ufw_allow_tcp_22() {
        let rule = make_rule(FirewallAction::Allow, FirewallProtocol::Tcp, None, Some(22));
        let cmd = compile_ufw(&rule);
        assert!(cmd.contains("ufw allow"));
        assert!(cmd.contains("proto tcp"));
        assert!(cmd.contains("port 22"));
    }

    #[test]
    fn test_compile_ufw_deny_from_cidr() {
        let rule = make_rule(
            FirewallAction::Deny,
            FirewallProtocol::Any,
            Some("10.0.0.0/8"),
            None,
        );
        let cmd = compile_ufw(&rule);
        assert!(cmd.contains("ufw deny"));
        assert!(cmd.contains("from 10.0.0.0/8"));
    }

    #[test]
    fn test_compile_firewalld_allow() {
        let rule = make_rule(
            FirewallAction::Allow,
            FirewallProtocol::Tcp,
            Some("10.0.0.0/8"),
            Some(443),
        );
        let cmd = compile_firewalld(&rule);
        assert!(cmd.contains("firewall-cmd"));
        assert!(cmd.contains("accept"));
        assert!(cmd.contains("10.0.0.0/8"));
        assert!(cmd.contains("443"));
    }

    #[test]
    fn test_compile_all_ufw() {
        let rules = vec![
            make_rule(FirewallAction::Allow, FirewallProtocol::Tcp, None, Some(22)),
            make_rule(
                FirewallAction::Deny,
                FirewallProtocol::Any,
                Some("10.0.0.0/8"),
                None,
            ),
        ];
        let cmds = compile_all(&rules, "ufw");
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].starts_with("ufw"));
    }
}
