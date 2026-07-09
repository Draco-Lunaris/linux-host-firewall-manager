//! Tests for the server-side rule policy engine (SEC-003)

use chrono::Utc;
use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
use fw_core::policy::{check_against_protected_cidrs, check_rule};
use uuid::Uuid;

fn make_rule(
    action: FirewallAction,
    src_cidr: Option<&str>,
    dst_port: Option<i32>,
) -> FirewallRule {
    FirewallRule {
        id: Uuid::nil(),
        name: "test".to_string(),
        description: String::new(),
        action,
        direction: FirewallDirection::In,
        protocol: FirewallProtocol::Tcp,
        src_cidr: src_cidr.map(|s| s.to_string()),
        src_port_start: None,
        src_port_end: None,
        dst_cidr: None,
        dst_port_start: dst_port,
        dst_port_end: dst_port,
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
fn test_broad_allow_requires_approval() {
    let rule = make_rule(FirewallAction::Allow, Some("0.0.0.0/0"), None);
    let result = check_rule(&rule);
    assert!(result.allowed);
    assert!(result.requires_approval);
    assert!(result.reason.contains("admin approval"));
}

#[test]
fn test_specific_allow_auto_approved() {
    let rule = make_rule(FirewallAction::Allow, Some("10.0.0.0/8"), Some(22));
    let result = check_rule(&rule);
    assert!(result.allowed);
    assert!(!result.requires_approval);
}

#[test]
fn test_deny_does_not_require_approval() {
    let rule = make_rule(FirewallAction::Deny, Some("0.0.0.0/0"), None);
    let result = check_rule(&rule);
    assert!(result.allowed);
    assert!(!result.requires_approval);
}

#[test]
fn test_protected_cidr_rejects_deny() {
    let rule = make_rule(FirewallAction::Deny, Some("10.0.0.0/8"), None);
    let protected = vec!["10.0.0.0/24".to_string()];
    let result = check_against_protected_cidrs(&rule, &protected);
    assert!(!result.allowed);
    assert!(result.reason.contains("protected CIDR"));
}

#[test]
fn test_protected_cidr_rejects_deny_single_ip() {
    let rule = make_rule(FirewallAction::Deny, Some("10.0.0.0/8"), None);
    let protected = vec!["10.0.0.5/32".to_string()];
    let result = check_against_protected_cidrs(&rule, &protected);
    assert!(!result.allowed);
}

#[test]
fn test_protected_cidr_allows_non_overlapping_deny() {
    let rule = make_rule(FirewallAction::Deny, Some("192.168.1.0/24"), None);
    let protected = vec!["10.0.0.5".to_string()];
    let result = check_against_protected_cidrs(&rule, &protected);
    assert!(result.allowed);
}

#[test]
fn test_protected_cidr_allows_allow_rule() {
    let rule = make_rule(FirewallAction::Allow, Some("10.0.0.0/8"), None);
    let protected = vec!["10.0.0.5".to_string()];
    let result = check_against_protected_cidrs(&rule, &protected);
    assert!(result.allowed);
}

#[test]
fn test_ipv6_broad_allow_requires_approval() {
    let rule = make_rule(FirewallAction::Allow, Some("::/0"), None);
    let result = check_rule(&rule);
    assert!(result.requires_approval);
}

#[test]
fn test_no_src_cidr_treated_as_broad() {
    let rule = make_rule(FirewallAction::Allow, None, None);
    let result = check_rule(&rule);
    assert!(result.requires_approval);
}
