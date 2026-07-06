use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
    Reporter,
    BreakGlassOperator,
}

impl UserRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "reporter" => Some(Self::Reporter),
            "break_glass_operator" => Some(Self::BreakGlassOperator),
            _ => None,
        }
    }
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }
    pub fn can_write(&self) -> bool {
        matches!(
            self,
            Self::Admin | Self::Operator | Self::BreakGlassOperator
        )
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Reporter => "reporter",
            Self::BreakGlassOperator => "break_glass_operator",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
    pub role: UserRole,
    pub ip: Option<IpAddr>,
    pub jti: String,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub verify_key_pem: String,
    pub ip_whitelist: Arc<RwLock<Vec<IpNet>>>,
    pub trusted_proxies: Arc<RwLock<Vec<IpNet>>>,
}

impl AuthConfig {
    pub async fn update_ip_whitelist(&self, list: Vec<IpNet>) {
        *self.ip_whitelist.write().await = list;
    }
    pub async fn update_trusted_proxies(&self, list: Vec<IpNet>) {
        *self.trusted_proxies.write().await = list;
    }
    pub async fn resolve_client_ip(&self, peer: IpAddr, xff: Option<&str>) -> Option<IpAddr> {
        let trusted = self.trusted_proxies.read().await;
        if trusted.is_empty() {
            return Some(peer);
        }
        let peer_net = IpNet::new(peer, if peer.is_ipv4() { 32 } else { 128 }).ok()?;
        let peer_trusted = trusted.iter().any(|t| t.contains(&peer_net.network()));
        if !peer_trusted {
            return Some(peer);
        }
        let xff = xff?;
        let leftmost = xff.split(',').next()?.trim();
        leftmost.parse::<IpAddr>().ok()
    }
}
