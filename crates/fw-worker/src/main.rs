use fw_core::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_worker=debug,fw_core=debug,info".into()),
        )
        .init();

    let config = AppConfig::load()?;
    let db = fw_core::db::init_pool(&config.database.url).await?;

    tracing::info!("fw-worker starting");
    let semaphore = tokio::sync::Semaphore::new(config.worker.max_concurrent_agent_calls);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
