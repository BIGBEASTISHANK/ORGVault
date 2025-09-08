use std::path::{PathBuf};
use tokio::fs;
use tokio::time::{Duration, interval};
use anyhow::Result;
use chrono::Utc;
use walkdir::WalkDir;

use crate::metadata::{SyncMetadata, FileRecord, calculate_checksum};
use crate::encryption::Encryptor;

pub struct SimpleSyncClient {
    sync_folder: PathBuf,
    metadata_file: PathBuf,
    metadata: SyncMetadata,
    encryptor: Encryptor,
    http_client: reqwest::Client,
}

impl SimpleSyncClient {
    pub async fn new(sync_folder: PathBuf) -> Result<Self> {
        fs::create_dir_all(&sync_folder).await?;
        
        let metadata_file = sync_folder.join(".sync_metadata.json");
        let mut metadata = SyncMetadata::load_from(&metadata_file)?;
        
        if metadata.server_url.is_empty() {
            metadata.server_url = "http://192.168.1.2:8080".to_string();
        }
        if metadata.client_id.is_empty() {
            metadata.client_id = get_mac_address().unwrap_or_else(|_| "default-client".to_string());
        }
        if metadata.encryption_key.is_none() {
            metadata.encryption_key = Some("shared-vault-key-2025".to_string());
        }
        
        metadata.save_to(&metadata_file)?;
        
        let encryptor = Encryptor::new(metadata.encryption_key.as_ref().unwrap());
        let http_client = reqwest::Client::new();
        
        println!("🔄 Simple sync client initialized");
        println!("📁 Sync folder: {:?}", sync_folder);
        println!("🌐 Server: {}", metadata.server_url);
        println!("🆔 Client ID: {}", metadata.client_id);
        
        Ok(Self {
            sync_folder,
            metadata_file,
            metadata,
            encryptor,
            http_client,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        println!("🚀 Starting simple file synchronization");
        
        // Test server connection first
        if let Err(e) = self.test_server_connection().await {
            println!("❌ Server connection test failed: {}", e);
            return Err(e);
        }
        
        // Initial sync - download everything from server
        self.download_all_files().await?;
        
        // Upload any local files
        self.upload_local_files().await?;
        
        // Start continuous sync loop
        let mut sync_interval = interval(Duration::from_secs(30));
        
        loop {
            sync_interval.tick().await;
            
            println!("🔄 Running sync cycle...");
            
            // Download new/changed files from server
            if let Err(e) = self.download_all_files().await {
                println!("❌ Download sync failed: {}", e);
            }
            
            // Upload any new local files
            if let Err(e) = self.upload_local_files().await {
                println!("❌ Upload sync failed: {}", e);
            }
            
            // Handle deletions (simple approach)
            // if let Err(e) = self.handle_deletions().await {
            //     println!("❌ Deletion sync failed: {}", e);
            // }
            
            // Save metadata
            self.metadata.last_sync = Some(Utc::now());
            let _ = self.metadata.save_to(&self.metadata_file);
            
            println!("✅ Sync cycle completed");
        }
    }

    async fn test_server_connection(&self) -> Result<()> {
        let url = format!("{}/api/server-info", self.metadata.server_url);
        
        println!("🔗 Testing server connection: {}", url);
        
        let response = self.http_client.get(&url).send().await?;
        
        if !response.status().is_success() {
            println!("❌ Server connection failed: {}", response.status());
            return Err(anyhow::anyhow!("Server connection failed: {}", response.status()));
        }
        
        println!("✅ Server connection successful");
        Ok(())
    }

    async fn download_all_files(&mut self) -> Result<()> {
        let url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}", 
                         self.metadata.server_url, self.metadata.client_id);
        
        println!("🔍 Requesting root folder from: {}", url);
        
        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => {
                println!("✅ Got response from server: {}", resp.status());
                resp
            },
            Err(e) => {
                println!("❌ Could not connect to server: {}", e);
                return Ok(());
            }
        };
        
        if !response.status().is_success() {
            println!("❌ Server returned error: {}", response.status());
            return Ok(());
        }
        
        let response_text = response.text().await?;
        println!("📋 Server response length: {} chars", response_text.len());
        println!("📋 Raw response: {}", response_text);
        
        let server_items: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(items) => {
                println!("✅ Successfully parsed JSON response");
                items
            },
            Err(e) => {
                println!("❌ Failed to parse JSON response: {}", e);
                println!("❌ Response was: {}", response_text);
                return Ok(());
            }
        };
        
        println!("📁 Found {} items in root folder", server_items.len());
        
        for (i, item) in server_items.iter().enumerate() {
            println!("📄 Item {}: {:?}", i + 1, item);
            
            if let Some(name) = item["name"].as_str() {
                let is_file = item["is_file"].as_bool().unwrap_or(false);
                
                println!("📂 Processing item: {} (is_file: {})", name, is_file);
                
                if is_file {
                    // Handle files in root folder
                    if !name.starts_with('.') {
                        println!("📄 Root file found: {}", name);
                        if let Err(e) = self.download_file(name).await {
                            println!("❌ Failed to download root file {}: {}", name, e);
                        } else {
                            println!("✅ Successfully downloaded root file: {}", name);
                        }
                    }
                } else {
                    // Handle subfolders (Team folders)
                    println!("📁 Team folder found: {} - downloading contents...", name);
                    if let Err(e) = self.download_folder_contents(name).await {
                        println!("❌ Failed to download folder {}: {}", name, e);
                    } else {
                        println!("✅ Successfully processed folder: {}", name);
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn download_folder_contents(&mut self, folder_name: &str) -> Result<()> {
        let folder_url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder/{}&mac={}", 
                                self.metadata.server_url, 
                                urlencoding::encode(folder_name),
                                self.metadata.client_id);
        
        println!("🔍 Exploring team folder: {} at {}", folder_name, folder_url);
        
        let response = match self.http_client.get(&folder_url).send().await {
            Ok(resp) => {
                println!("✅ Got folder response: {}", resp.status());
                resp
            },
            Err(e) => {
                println!("❌ Could not access folder {}: {}", folder_name, e);
                return Ok(());
            }
        };
        
        if !response.status().is_success() {
            println!("❌ Folder {} returned error: {}", folder_name, response.status());
            return Ok(());
        }
        
        let response_text = response.text().await?;
        println!("📋 Folder '{}' response length: {} chars", folder_name, response_text.len());
        println!("📋 Folder '{}' raw response: {}", folder_name, response_text);
        
        let folder_items: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(items) => {
                println!("✅ Successfully parsed folder JSON");
                items
            },
            Err(e) => {
                println!("❌ Failed to parse folder {} response: {}", folder_name, e);
                return Ok(());
            }
        };
        
        println!("📁 Team folder '{}' contains {} items", folder_name, folder_items.len());
        
        for (i, item) in folder_items.iter().enumerate() {
            println!("   📄 Folder item {}: {:?}", i + 1, item);
            
            if let Some(file_name) = item["name"].as_str() {
                let is_file = item["is_file"].as_bool().unwrap_or(false);
                
                println!("   📂 Processing folder item: {} (is_file: {})", file_name, is_file);
                
                if is_file && !file_name.starts_with('.') {
                    let relative_path = format!("{}/{}", folder_name, file_name);
                    let local_path = self.sync_folder.join(&relative_path);
                    
                    println!("   📥 Found file to download: {}", relative_path);
                    println!("   💾 Local path will be: {:?}", local_path);
                    
                    // Check if file needs downloading
                    let should_download = if local_path.exists() {
                        if let Ok(local_metadata) = fs::metadata(&local_path).await {
                            if let Some(server_size) = item["size"].as_u64() {
                                let size_different = local_metadata.len() != server_size;
                                println!("   📊 Size comparison for {}: local={}, server={}, different={}", 
                                        relative_path, local_metadata.len(), server_size, size_different);
                                size_different
                            } else {
                                println!("   ⚠️ No server size available for {}", relative_path);
                                false
                            }
                        } else {
                            println!("   📄 Cannot read local metadata for {}", relative_path);
                            true
                        }
                    } else {
                        println!("   📄 New file detected: {}", relative_path);
                        true
                    };
                    
                    if should_download {
                        println!("   📥 Downloading team file: {}", relative_path);
                        if let Err(e) = self.download_file(&relative_path).await {
                            println!("   ❌ Failed to download {}: {}", relative_path, e);
                        } else {
                            println!("   ✅ Successfully downloaded: {}", relative_path);
                        }
                    } else {
                        println!("   ⏭️ Skipping unchanged file: {}", relative_path);
                    }
                } else if !is_file {
                    println!("   📁 Nested folder found: {}/{} (not implemented)", folder_name, file_name);
                }
            }
        }
        
        Ok(())
    }

    async fn download_file(&mut self, relative_path: &str) -> Result<()> {
        let download_url = format!("{}/api/download/{}?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                  self.metadata.server_url, 
                                  urlencoding::encode(relative_path),
                                  self.metadata.client_id);
        
        println!("   📥 Starting download: {} from {}", relative_path, download_url);
        
        let response = self.http_client.get(&download_url).send().await?;
        
        if !response.status().is_success() {
            println!("   ❌ Download failed for {}: HTTP {}", relative_path, response.status());
            return Err(anyhow::anyhow!("Download failed: HTTP {}", response.status()));
        }
        
        println!("   ✅ Download response OK for: {}", relative_path);
        
        // Get all bytes at once (simplified approach)
        let content = response.bytes().await?;
        println!("   📦 Downloaded {} bytes for: {}", content.len(), relative_path);
        
        // Try to decrypt - if it fails, use raw data
        let final_data = match self.encryptor.decrypt(&content) {
            Ok(decrypted) => {
                println!("   🔓 File decrypted successfully: {}", relative_path);
                decrypted
            }
            Err(e) => {
                println!("   📄 Using raw data (decryption failed: {}): {}", e, relative_path);
                content.to_vec()
            }
        };
        
        let local_path = self.sync_folder.join(relative_path);
        
        // Create parent directories
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
            println!("   📁 Created directory structure: {:?}", parent);
        }
        
        // Write file to disk
        fs::write(&local_path, &final_data).await?;
        println!("   💾 Saved file: {} ({} bytes) to {:?}", relative_path, final_data.len(), local_path);
        
        // Update metadata
        let file_record = FileRecord {
            path: relative_path.to_string(),
            size: final_data.len() as u64,
            modified: Utc::now(),
            checksum: calculate_checksum(&final_data),
            encrypted: false,
        };
        
        self.metadata.update_file_record(file_record);
        
        Ok(())
    }

    async fn upload_local_files(&mut self) -> Result<()> {
        println!("📤 Checking for local files to upload...");
        
        for entry in WalkDir::new(&self.sync_folder) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    // Skip hidden files and metadata
                    if filename.starts_with('.') {
                        continue;
                    }
                    
                    let relative_path = entry.path().strip_prefix(&self.sync_folder)?;
                    let path_str = relative_path.to_string_lossy().to_string();
                    
                    // Check if we need to upload this file
                    let needs_upload = if let Some(record) = self.metadata.get_file_record(&path_str) {
                        let file_data = fs::read(entry.path()).await?;
                        let current_checksum = calculate_checksum(&file_data);
                        current_checksum != record.checksum
                    } else {
                        true // New file
                    };
                    
                    if needs_upload {
                        println!("📤 Uploading: {}", path_str);
                        if let Err(e) = self.upload_file(&path_str).await {
                            println!("❌ Failed to upload {}: {}", path_str, e);
                        } else {
                            println!("✅ Uploaded: {}", path_str);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn upload_file(&mut self, relative_path: &str) -> Result<()> {
        let local_path = self.sync_folder.join(relative_path);
        let file_data = fs::read(&local_path).await?;
        
        let encrypted_data = self.encryptor.encrypt(&file_data)?;
        
        let upload_url = format!("{}/api/upload?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                self.metadata.server_url, self.metadata.client_id);
        
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(encrypted_data)
                .file_name(relative_path.to_string()));
        
        let response = self.http_client.post(&upload_url).multipart(form).send().await?;
        
        if response.status().is_success() {
            let file_record = FileRecord {
                path: relative_path.to_string(),
                size: file_data.len() as u64,
                modified: Utc::now(),
                checksum: calculate_checksum(&file_data),
                encrypted: false,
            };
            
            self.metadata.update_file_record(file_record);
        } else {
            return Err(anyhow::anyhow!("Upload failed: {}", response.status()));
        }
        
        Ok(())
    }

    async fn handle_deletions(&mut self) -> Result<()> {
    println!("🗑️ Checking for files to delete...");
    
    // Skip deletion for now - it's removing valid files
    println!("⏭️ Skipping deletion check to prevent removing valid files");
    
    Ok(())
}

}

fn get_mac_address() -> Result<String> {
    use std::process::Command;
    
    #[cfg(target_os = "linux")]
    {
        let interfaces = ["eno1", "eth0", "wlo1", "wlan0"];
        for interface in &interfaces {
            let path = format!("/sys/class/net/{}/address", interface);
            if let Ok(output) = Command::new("cat").arg(&path).output() {
                if output.status.success() {
                    let mac = String::from_utf8(output.stdout)?.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return Ok(mac);
                    }
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Could not detect MAC address"))
}
