use std::path::PathBuf;
use anyhow::Result;

mod simple_sync;
mod encryption;
mod metadata;

use simple_sync::SimpleSyncClient;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting Simple Sync Client");

    let sync_folder = dirs::document_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("SecureVaultSync");

    let mut client = SimpleSyncClient::new(sync_folder).await?;
    client.start().await?;
    
    Ok(())
}
