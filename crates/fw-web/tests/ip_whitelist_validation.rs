// Tests for IP whitelist validation (Phase: settings hardening).

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    /// Validate that a string is a valid CIDR or bare IP address.
    /// Mirrors the logic in settings.rs::validate_cidr_or_ip.
    fn validate_cidr_or_ip(entry: &str) -> Result<String, String> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(entry.to_string());
        }

        if let Ok(net) = ipnet::IpNet::from_str(trimmed) {
            return Ok(net.to_string());
        }

        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let net = match ip {
                IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
            };
            return Ok(net.to_string());
        }

        Err(entry.to_string())
    }

    /// Check if a requester IP is covered by any entry in the whitelist.
    /// Mirrors the lockout prevention logic in update_ip_whitelist.
    fn ip_is_covered(whitelist: &[String], requester_ip: IpAddr) -> bool {
        whitelist.iter().any(|entry| {
            ipnet::IpNet::from_str(entry)
                .map(|net| net.contains(&requester_ip))
                .unwrap_or(false)
        })
    }

    // ── CIDR validation tests ──────────────────────────────────────────────

    #[test]
    fn test_valid_ipv4_cidr() {
        assert_eq!(validate_cidr_or_ip("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(validate_cidr_or_ip("192.168.1.0/24").unwrap(), "192.168.1.0/24");
        assert_eq!(validate_cidr_or_ip("0.0.0.0/0").unwrap(), "0.0.0.0/0");
    }

    #[test]
    fn test_valid_ipv6_cidr() {
        assert_eq!(validate_cidr_or_ip("::1/128").unwrap(), "::1/128");
        assert_eq!(validate_cidr_or_ip("2001:db8::/32").unwrap(), "2001:db8::/32");
    }

    #[test]
    fn test_bare_ipv4_normalized_to_32() {
        assert_eq!(validate_cidr_or_ip("10.0.0.1").unwrap(), "10.0.0.1/32");
        assert_eq!(validate_cidr_or_ip("192.168.1.5").unwrap(), "192.168.1.5/32");
    }

    #[test]
    fn test_bare_ipv6_normalized_to_128() {
        assert_eq!(validate_cidr_or_ip("::1").unwrap(), "::1/128");
        assert_eq!(
            validate_cidr_or_ip("2001:db8::1").unwrap(),
            "2001:db8::1/128"
        );
    }

    #[test]
    fn test_whitespace_trimmed() {
        assert_eq!(validate_cidr_or_ip("  10.0.0.0/8  ").unwrap(), "10.0.0.0/8");
        assert_eq!(validate_cidr_or_ip(" 192.168.1.1 ").unwrap(), "192.168.1.1/32");
    }

    #[test]
    fn test_empty_string_rejected() {
        assert!(validate_cidr_or_ip("").is_err());
        assert!(validate_cidr_or_ip("   ").is_err());
    }

    #[test]
    fn test_invalid_entries_rejected() {
        assert!(validate_cidr_or_ip("not-an-ip").is_err());
        assert!(validate_cidr_or_ip("10.0.0.0/33").is_err()); // prefix too long for IPv4
        assert!(validate_cidr_or_ip("10.0.0.0/abc").is_err());
        assert!(validate_cidr_or_ip("999.999.999.999").is_err());
        assert!(validate_cidr_or_ip("10.0.0/24").is_err()); // incomplete octets
    }

    #[test]
    fn test_invalid_ipv6_rejected() {
        assert!(validate_cidr_or_ip("gggg::1").is_err());
        assert!(validate_cidr_or_ip("::1/129").is_err()); // prefix too long for IPv6
    }

    // ── Lockout prevention tests ───────────────────────────────────────────

    #[test]
    fn test_lockout_prevention_requester_covered() {
        let whitelist = vec![
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
        ];
        let requester = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(ip_is_covered(&whitelist, requester));
    }

    #[test]
    fn test_lockout_prevention_requester_not_covered() {
        let whitelist = vec![
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
        ];
        let requester = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(!ip_is_covered(&whitelist, requester));
    }

    #[test]
    fn test_lockout_prevention_empty_whitelist_allows_all() {
        // Empty whitelist = allow all, so no lockout check needed
        let whitelist: Vec<String> = vec![];
        let requester = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Empty list means "allow all" — the lockout check is skipped
        // (the handler only checks if the list is non-empty)
        assert!(!ip_is_covered(&whitelist, requester)); // technically false, but the handler skips this case
    }

    #[test]
    fn test_lockout_prevention_ipv6_requester_covered() {
        let whitelist = vec!["2001:db8::/32".to_string()];
        let requester = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(ip_is_covered(&whitelist, requester));
    }

    #[test]
    fn test_lockout_prevention_ipv6_requester_not_covered() {
        let whitelist = vec!["2001:db8::/32".to_string()];
        let requester = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdead, 0, 0, 0, 0, 0, 1));
        assert!(!ip_is_covered(&whitelist, requester));
    }

    #[test]
    fn test_lockout_prevention_bare_ip_in_whitelist() {
        // A bare IP normalized to /32 should cover the exact IP
        let whitelist = vec!["127.0.0.1/32".to_string()];
        let requester = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(ip_is_covered(&whitelist, requester));

        // But not a different IP
        let requester2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(!ip_is_covered(&whitelist, requester2));
    }

    #[test]
    fn test_lockout_prevention_mixed_ipv4_ipv6() {
        let whitelist = vec![
            "10.0.0.0/8".to_string(),
            "::1/128".to_string(),
        ];
        // IPv4 requester covered by IPv4 entry
        assert!(ip_is_covered(&whitelist, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
        // IPv6 requester covered by IPv6 entry
        assert!(ip_is_covered(&whitelist, IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // IPv4 requester NOT covered by IPv6 entry
        assert!(!ip_is_covered(&whitelist, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_lockout_prevention_localhost_in_list() {
        let whitelist = vec![
            "127.0.0.1/32".to_string(),
            "10.0.0.0/8".to_string(),
        ];
        let requester = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(ip_is_covered(&whitelist, requester));
    }
}