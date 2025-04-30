use anyhow::Result;
use core::cli::BBHuntCli;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging and tracing
    tracing_subscriber::fmt::init();

    // Initialize and run the CLI
    let cli = BBHuntCli::new();
    cli.run().await
}
