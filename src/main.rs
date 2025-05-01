use anyhow::Result;
use bbhunt::cli::app::App;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create and run the application
    let mut app = App::new()?;
    app.run().await
}