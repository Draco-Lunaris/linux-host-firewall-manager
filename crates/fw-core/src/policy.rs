use crate::models::FirewallRule;

#[derive(Debug, Clone)]
pub struct PolicyCheckResult {
    pub allowed: bool,
    pub requires_approval: bool,
    pub reason: String,
}

pub fn check_rule(rule: &FirewallRule) -> PolicyCheckResult {
    if rule.action == crate::models::FirewallAction::Allow {
        let is_broad_src = rule
            .src_cidr
            .as_ref()
            .map(|c| c == "0.0.0.0/0" || c == "::/0" || c == "any")
            .unwrap_or(true);
        let is_broad_dst_port = rule.dst_port_start.is_none()
            || (rule.dst_port_start.is_none() && rule.dst_port_end.is_none());

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

pub fn check_against_protected_cidrs(
    rule: &FirewallRule,
    protected_cidrs: &[String],
) -> PolicyCheckResult {
    if rule.action == crate::models::FirewallAction::Deny
        || rule.action == crate::models::FirewallAction::Reject
    {
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
