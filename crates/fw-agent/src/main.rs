#![allow(clippy::too_many_arguments)]
use anyhow::Context;
use fw_agent::pull_client;

mod backend;
mod config;
mod drift;
mod enrollment;
mod protected_cidrs;
mod pull_loop;
mod replay_cache;
mod safe_mode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fw-agent")]
#[command(about = "Linux Host Firewall Manager — per-host agent")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll this host with a firewall manager
    Enroll {
        #[arg(long)]
        manager_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        fqdn: String,
    },
    /// Run the agent daemon (normally started by systemd)
    Run,
    /// Show agent status: enrollment, backend, last sync
    Status,
    /// Preview what the next job would do without touching rules
    Apply {
        #[arg(long)]
        dry_run: bool,
    },
    /// Check for rule drift (compare current rules to last snapshot)
    DriftCheck,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_agent=debug,info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Enroll {
            manager_url,
            token,
            fqdn,
        }) => {
            enrollment::enroll(&manager_url, &token, &fqdn).await?;
        }
        Some(Commands::Run) => {
            run_daemon().await?;
        }
        Some(Commands::Status) => {
            status_report().await?;
        }
        Some(Commands::Apply { dry_run }) => {
            if dry_run {
                println!("Dry-run: would apply rules from next job");
                // In production: fetch pending job from manager, compile, print commands
            } else {
                println!("Manual apply not supported in daemon mode — use the manager UI");
            }
        }
        Some(Commands::DriftCheck) => {
            drift::check().await?;
        }
        None => {
            println!("fw-agent — Linux Host Firewall Manager agent");
            println!();
            println!("Usage: fw-agent <COMMAND>");
            println!();
            println!("Commands:");
            println!("  enroll       Enroll this host with a firewall manager");
            println!("  run          Run the agent daemon (normally started by systemd)");
            println!("  status       Show agent status: enrollment, backend, last sync");
            println!("  apply        Preview or apply rules (--dry-run to preview only)");
            println!("  drift-check  Check for rule drift");
            println!();
            println!("Run 'fw-agent <command> --help' for more information.");
        }
    }
    Ok(())
}

/// Run the agent daemon — starts the pull loop (the only apply path in the
/// pull model; the manager never contacts the agent).
async fn run_daemon() -> anyhow::Result<()> {
    // Block until the agent is enrolled (host_id + mTLS certs present). If a
    // one-time token is present, enroll in-process; otherwise wait for a token
    // to appear or for a manual `fw-agent enroll` to complete. This keeps the
    // daemon from crash-looping before enrollment.
    let cfg = wait_for_enrollment().await?;

    let host_id = cfg
        .host_id
        .as_ref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("No host_id in config — re-enroll required"))?;

    // Load mTLS certs for the pull client
    let cert_dir = &cfg.cert_dir;
    let client_cert = std::fs::read_to_string(format!("{}/server.pem", cert_dir))
        .or_else(|_| std::fs::read_to_string(format!("{}/agent.pem", cert_dir)))
        .context("Failed to read client certificate")?;
    let client_key = std::fs::read_to_string(format!("{}/server.key.pem", cert_dir))
        .or_else(|_| std::fs::read_to_string(format!("{}/agent.key.pem", cert_dir)))
        .context("Failed to read client key")?;
    let ca_cert = std::fs::read_to_string(format!("{}/ca.pem", cert_dir))
        .context("Failed to read CA certificate")?;

    // Create the pull client. `manager_agent_url` is the base URL of the
    // manager's mTLS agent API (e.g. "https://mgr:8443"); the pull client
    // appends the endpoint paths. It is always set by a successful enrollment,
    // so an empty value means the config is stale — re-enroll rather than fall
    // back to the human-UI `manager_url` (port 443), which does not mount the
    // agent API and would 404 every check-in.
    let manager_url = cfg.pull.manager_agent_url.clone();
    if manager_url.is_empty() {
        anyhow::bail!("manager_agent_url is not set in config — run 'fw-agent enroll' first");
    }
    let pull_client =
        pull_client::PullClient::new(&manager_url, host_id, &client_cert, &client_key, &ca_cert)?;

    // Detect the firewall backend
    let backend = backend::detect().ok_or_else(|| {
        anyhow::anyhow!("No firewall backend detected (ufw/firewalld/nftables required)")
    })?;
    let backend: std::sync::Arc<dyn backend::FirewallBackend> = std::sync::Arc::from(backend);

    let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg.clone()));

    // Start the pull loop as a background task
    let pull_backend = backend.clone();
    let pull_config = config.clone();
    tokio::spawn(async move {
        pull_loop::run_pull_loop(pull_backend, pull_config, pull_client).await;
    });
    tracing::info!("Pull loop started (pull-only mode)");

    // No push server in the pull model — the manager never contacts the agent.
    tokio::signal::ctrl_c().await?;
    tracing::info!("Agent shutting down");

    Ok(())
}

/// Path to the one-time enrollment token written by the installer. The daemon
/// reads it to enroll in-process, so the secret never appears in a service
/// file or process list.
const ENROLL_TOKEN_PATH: &str = "/etc/firewall-agent/enroll.token";

/// Block until the agent is enrolled (a valid host_id plus the mTLS client
/// cert, key, and CA are present). While not enrolled:
///   • if a token is present at [ENROLL_TOKEN_PATH], run enrollment in-process
///     (it writes the certs and updates the config, then we reload);
///   • otherwise wait for a token to appear or for a manual `fw-agent enroll`
///     to complete.
///
/// This never returns `Err` for the "not enrolled yet" state — the daemon
/// blocks here rather than exiting, so systemd does not crash-loop it before
/// enrollment.
async fn wait_for_enrollment() -> anyhow::Result<config::AgentConfig> {
    let mut hint_logged = false;

    loop {
        let cfg = match config::AgentConfig::load() {
            Some(c) => c,
            None => {
                if !hint_logged {
                    tracing::warn!(
                        "No agent config at {} — waiting for it to appear",
                        config::AgentConfig::config_path()
                    );
                    hint_logged = true;
                }
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                continue;
            }
        };

        if is_enrolled(&cfg) {
            tracing::info!("Agent enrolled — starting pull loop");
            return Ok(cfg);
        }

        match std::fs::read_to_string(ENROLL_TOKEN_PATH) {
            Ok(token) if !token.trim().is_empty() => {
                let manager_url = cfg.manager_url.clone();
                let fqdn = cfg.fqdn.clone();
                if manager_url.is_empty() || fqdn.is_empty() {
                    tracing::warn!(
                        "Enrollment token present but manager_url/fqdn not set in {} — set them to enroll",
                        config::AgentConfig::config_path()
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
                tracing::info!("Starting enrollment with {}", manager_url);
                match enrollment::enroll(&manager_url, token.trim(), &fqdn).await {
                    // Enrollment wrote the certs and updated the config on
                    // disk — loop to reload and confirm enrollment.
                    Ok(()) => continue,
                    Err(e) => {
                        tracing::error!("Enrollment failed: {e} — retrying in 60s");
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        continue;
                    }
                }
            }
            _ => {
                if !hint_logged {
                    tracing::info!(
                        "Not enrolled. Provide a token at {} (or run 'fw-agent enroll --manager-url <URL> --token <TOKEN> --fqdn <FQDN>') to enroll.",
                        ENROLL_TOKEN_PATH
                    );
                    hint_logged = true;
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
        }
    }
}

/// Enrolled = a parseable host_id is set AND the mTLS client cert, key, and CA
/// are present on disk.
fn is_enrolled(cfg: &config::AgentConfig) -> bool {
    let has_host_id = cfg
        .host_id
        .as_ref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .is_some();
    if !has_host_id {
        return false;
    }
    let d = &cfg.cert_dir;
    let cert = std::path::Path::new(&format!("{d}/server.pem")).exists()
        || std::path::Path::new(&format!("{d}/agent.pem")).exists();
    let key = std::path::Path::new(&format!("{d}/server.key.pem")).exists()
        || std::path::Path::new(&format!("{d}/agent.key.pem")).exists();
    let ca = std::path::Path::new(&format!("{d}/ca.pem")).exists();
    cert && key && ca
}

async fn status_report() -> anyhow::Result<()> {
    let cfg = config::AgentConfig::load();
    if let Some(c) = cfg {
        println!("Manager URL: {}", c.manager_url);
        println!("FQDN: {}", c.fqdn);
        if let Some(id) = c.host_id {
            println!("Host ID: {}", id);
        }
        println!(
            "Safe mode: {} (timeout: {}s)",
            if c.safe_mode_enabled {
                "enabled"
            } else {
                "disabled"
            },
            c.safe_mode_timeout_secs
        );
        if !c.protected_cidrs.is_empty() {
            println!("Protected CIDRs: {}", c.protected_cidrs.join(", "));
        }
    } else {
        println!(
            "Not enrolled (no config found at {})",
            config::AgentConfig::config_path()
        );
        println!(
            "Run: fw-agent enroll --manager-url https://fwm.internal --token <TOKEN> --fqdn <FQDN>"
        );
    }

    println!();

    // Check certs
    let cert_dir = "/etc/firewall-agent/certs";
    let ca_exists = std::path::Path::new(&format!("{}/ca.pem", cert_dir)).exists();
    let cert_exists = std::path::Path::new(&format!("{}/server.pem", cert_dir)).exists();
    let key_exists = std::path::Path::new(&format!("{}/server.key.pem", cert_dir)).exists();
    println!("Certificates:");
    println!(
        "  CA:         {}",
        if ca_exists { "present" } else { "missing" }
    );
    println!(
        "  Server cert: {}",
        if cert_exists { "present" } else { "missing" }
    );
    println!(
        "  Server key:  {}",
        if key_exists { "present" } else { "missing" }
    );

    println!();

    // Check backend
    if let Some(backend) = backend::detect() {
        println!("Backend: {}", backend.name());
        if let Ok(status) = backend.status().await {
            println!("  Active: {}", status.active);
            println!("  Default policy (in):  {}", status.default_policy_in);
            println!("  Default policy (out): {}", status.default_policy_out);
        }
    } else {
        println!("Backend: none detected");
    }

    println!();

    // Check container runtime
    if let Some(runtime) = backend::container_detect::detect_container_runtime() {
        println!("Container runtime: {} (WARNING: UFW may conflict)", runtime);
    } else {
        println!("Container runtime: none detected");
    }

    Ok(())
}
