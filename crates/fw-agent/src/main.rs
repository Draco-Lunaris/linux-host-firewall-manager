mod backend;
mod compiler;
mod config;
mod drift;
mod enrollment;
mod mtls;
mod routes;
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
    Enroll {
        #[arg(long)]
        manager_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        fqdn: String,
    },
    Run,
    Status,
    Apply {
        #[arg(long)]
        dry_run: bool,
    },
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
            println!(
                "Enrolling with {} as {} (token: {}...)",
                manager_url,
                fqdn,
                &token[..8.min(token.len())]
            );
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
            } else {
                println!("Manual apply not supported in daemon mode");
            }
        }
        Some(Commands::DriftCheck) => {
            drift::check().await?;
        }
        None => {
            println!("fw-agent — use --help for usage");
        }
    }
    Ok(())
}

async fn status_report() -> anyhow::Result<()> {
    let cfg = config::load();
    if let Some(c) = cfg {
        println!("Manager URL: {}", c.manager_url);
        println!("FQDN: {}", c.fqdn);
    } else {
        println!("Not enrolled (no config found)");
    }
    if let Some(backend) = backend::detect() {
        println!("Backend: {}", backend.name());
    } else {
        println!("Backend: none detected");
    }
    Ok(())
}
