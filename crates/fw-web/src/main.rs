use fw_core::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fw_web=debug,fw_core=debug,info".into()),
        )
        .init();

    let config = AppConfig::load()?;
    fw_web::run().await
}
