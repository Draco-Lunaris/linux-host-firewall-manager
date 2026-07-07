mod backend;
mod compiler;
mod config;
mod drift;
mod enrollment;
mod mtls;
mod protected_cidrs;
mod routes;
mod safe_mode;
mod server;

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
            server::run().await?;
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

async fn status_report() -> anyhow::Result<()> {
    let cfg = config::AgentConfig::load();
    if let Some(c) = cfg {
        println!("Manager URL: {}", c.manager_url);
        println!("FQDN: {}", c.fqdn);
        if let Some(id) = c.host_id {
            println!("Host ID: {}", id);
        }
        println!("Listen port: {}", c.listen_port);
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
