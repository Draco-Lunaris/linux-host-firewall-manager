pub fn load_certs() -> Option<(String, String, String)> {
    let base = "/etc/firewall-agent/certs";
    let ca = std::fs::read_to_string(format!("{}/ca.pem", base)).ok()?;
    let cert = std::fs::read_to_string(format!("{}/server.pem", base)).ok()?;
    let key = std::fs::read_to_string(format!("{}/server.key.pem", base)).ok()?;
    Some((ca, cert, key))
}
