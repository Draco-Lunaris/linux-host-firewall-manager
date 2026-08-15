use crate::models::{FirewallAction, FirewallRule};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PolicyCheckResult {
    pub allowed: bool,
    pub requires_approval: bool,
    pub reason: String,
}

pub fn check_rule(rule: &FirewallRule) -> PolicyCheckResult {
    if rule.action == FirewallAction::Allow {
        let is_broad_src = rule
            .src_cidr
            .as_ref()
            .map(|c| c == "0.0.0.0/0" || c == "::/0" || c == "any")
            .unwrap_or(true);
        let is_broad_dst_port = rule.dst_port_start.is_none() && rule.dst_port_end.is_none();

        if is_broad_src && is_broad_dst_port {
            return PolicyCheckResult {
                allowed: true,
                requires_approval: true,
                reason: "Broad allow rule (any source, any port) requires admin approval"
                    .to_string(),
            };
        }
    }

    PolicyCheckResult {
        allowed: true,
        requires_approval: false,
        reason: "Auto-approved".to_string(),
    }
}

/// The IDs of the rules in `rules` that are flagged (require admin approval) —
/// i.e. broad allow rules. Used by the SEC-003 assignment gate.
pub fn check_policy_set_for_flagged(rules: &[FirewallRule]) -> Vec<Uuid> {
    rules
        .iter()
        .filter(|r| check_rule(r).requires_approval)
        .map(|r| r.id)
        .collect()
}

/// Fetch a policy set's rules from the DB and return the IDs of the flagged
/// ones. Shared by the assignment gates in hosts.rs and deployment.rs.
pub async fn flagged_rule_ids_for_set(
    db: &sqlx::PgPool,
    policy_set_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rules: Vec<FirewallRule> = sqlx::query_as(
        "SELECT r.* FROM firewall_rules r
         JOIN firewall_policy_set_rules psr ON psr.rule_id = r.id
         WHERE psr.policy_set_id = $1",
    )
    .bind(policy_set_id)
    .fetch_all(db)
    .await?;
    Ok(check_policy_set_for_flagged(&rules))
}

pub fn check_against_protected_cidrs(
    rule: &FirewallRule,
    protected_cidrs: &[String],
) -> PolicyCheckResult {
    if rule.action == FirewallAction::Deny || rule.action == FirewallAction::Reject {
        if let Some(src) = &rule.src_cidr {
            for protected in protected_cidrs {
                if cidr_overlaps(src, protected) {
                    return PolicyCheckResult {
                        allowed: false,
                        requires_approval: false,
                        reason: format!("Rule blocks protected CIDR {} — rejected", protected),
                    };
                }
            }
        }
    }
    PolicyCheckResult {
        allowed: true,
        requires_approval: false,
        reason: "Does not block protected CIDRs".to_string(),
    }
}

fn cidr_overlaps(a: &str, b: &str) -> bool {
    use ipnet::IpNet;
    let net_a = match a.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let net_b = match b.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => return false,
    };
    if net_a.network().is_ipv4() != net_b.network().is_ipv4() {
        return false;
    }
    net_a.contains(&net_b.network()) || net_b.contains(&net_a.network())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FirewallAction, FirewallDirection, FirewallProtocol};
    use chrono::Utc;

    fn rule(
        id: u128,
        action: FirewallAction,
        src: Option<&str>,
        dst_port: Option<i32>,
    ) -> FirewallRule {
        FirewallRule {
            id: Uuid::from_u128(id),
            name: format!("rule-{id}"),
            description: String::new(),
            action,
            direction: FirewallDirection::In,
            protocol: FirewallProtocol::Any,
            src_cidr: src.map(|s| s.to_string()),
            src_port_start: None,
            src_port_end: None,
            dst_cidr: None,
            dst_port_start: dst_port,
            dst_port_end: dst_port,
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
    fn flags_broad_allow_only() {
        let rules = vec![
            rule(1, FirewallAction::Allow, None, None), // broad allow -> flagged
            rule(2, FirewallAction::Allow, Some("0.0.0.0/0"), None), // broad allow -> flagged
            rule(3, FirewallAction::Allow, Some("10.0.0.0/8"), None), // narrow src -> not flagged
            rule(4, FirewallAction::Allow, None, Some(22)), // has dst port -> not flagged
            rule(5, FirewallAction::Deny, None, None),  // deny -> not flagged
        ];
        let flagged = check_policy_set_for_flagged(&rules);
        assert_eq!(flagged.len(), 2);
        assert!(flagged.contains(&Uuid::from_u128(1)));
        assert!(flagged.contains(&Uuid::from_u128(2)));
    }
}
