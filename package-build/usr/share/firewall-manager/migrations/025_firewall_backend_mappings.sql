-- Migration: 025_firewall_backend_mappings
-- Description: OS family → preferred firewall backend mapping
-- Agent uses this as a hint; actual detection is done on the host.

CREATE TABLE IF NOT EXISTS firewall_backend_mappings (
    os_family       TEXT NOT NULL PRIMARY KEY,
    preferred_backend TEXT NOT NULL CHECK (preferred_backend IN ('ufw', 'firewalld', 'nftables', 'iptables')),
    fallback_backend TEXT CHECK (fallback_backend IS NULL OR fallback_backend IN ('ufw', 'firewalld', 'nftables', 'iptables'))
);

INSERT INTO firewall_backend_mappings (os_family, preferred_backend, fallback_backend) VALUES
    ('debian', 'ufw', 'iptables'),
    ('ubuntu', 'ufw', 'iptables'),
    ('rhel',   'firewalld', 'iptables'),
    ('fedora', 'firewalld', 'iptables'),
    ('almalinux', 'firewalld', 'iptables'),
    ('alpine', 'iptables', NULL),
    ('arch',   'iptables', NULL)
ON CONFLICT (os_family) DO NOTHING;