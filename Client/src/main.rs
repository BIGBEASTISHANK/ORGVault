use std::path::PathBuf;
use anyhow::Result;
use log::info;

mod sync_client;
mod encryption;
mod metadata;

use sync_client::SyncClient;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("🚀 Starting Secure Vault Desktop Client");

    let sync_folder = dirs::document_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("SecureVaultSync");

    let mut client = SyncClient::new(sync_folder).await?;
    client.start_sync().await?;
    
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
