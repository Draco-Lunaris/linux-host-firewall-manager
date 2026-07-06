#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("migrate-secrets: one-shot AES-GCM migration tool");
    println!("Usage: DATABASE_URL=... cargo run -p migrate-secrets");
    Ok(())
}
