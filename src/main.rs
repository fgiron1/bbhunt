use bbhunt::cli::app::App;
use tracing_subscriber;
use bbhunt::error::{BBHuntResult, BBHuntError, util::log_error};

#[tokio::main]
async fn main() -> BBHuntResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create and initialize the application
    let mut app = App::new();
    
    // Initialize app context
    if let Err(e) = app.initialize().await {
        eprintln!("Error initializing application: {}", e);
        return Err(e);
    }
    
    // Get context and initialize templates
    let context = app.context()?;
    
    // Run the application
    match app.run().await {
        Ok(_) => {
            println!("Application completed successfully");
            Ok(())
        },
        Err(e) => {
            eprintln!("Application error: {}", e);
            Err(e)
        }
    }
}