use std::path::{PathBuf};
use tokio::fs;
use tokio::time::{Duration, interval};
use anyhow::Result;
use log::{info, warn, error};
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
        
        info!("🔄 Simple sync client initialized");
        info!("📁 Sync folder: {:?}", sync_folder);
        info!("🌐 Server: {}", metadata.server_url);
        info!("🆔 Client ID: {}", metadata.client_id);
        
        Ok(Self {
            sync_folder,
            metadata_file,
            metadata,
            encryptor,
            http_client,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("🚀 Starting simple file synchronization");
        
        // Test server connection first
        if let Err(e) = self.test_server_connection().await {
            error!("Server connection test failed: {}", e);
            return Err(e);
        }
        
        // Initial sync - download everything from server
        self.download_all_files().await?;
        
        // Upload any local files
        self.upload_local_files().await?;
        
        // Start continuous sync loop
        let mut sync_interval = interval(Duration::from_secs(10));
        
        loop {
            sync_interval.tick().await;
            
            info!("🔄 Running sync cycle...");
            
            // Download new/changed files from server
            if let Err(e) = self.download_all_files().await {
                error!("Download sync failed: {}", e);
            }
            
            // Upload any new local files
            if let Err(e) = self.upload_local_files().await {
                error!("Upload sync failed: {}", e);
            }
            
            // Handle deletions (simple approach)
            if let Err(e) = self.handle_deletions().await {
                error!("Deletion sync failed: {}", e);
            }
            
            // Save metadata
            self.metadata.last_sync = Some(Utc::now());
            let _ = self.metadata.save_to(&self.metadata_file);
            
            info!("✅ Sync cycle completed");
        }
    }

    async fn test_server_connection(&self) -> Result<()> {
        let url = format!("{}/api/server-info", self.metadata.server_url);
        
        let response = self.http_client.get(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Server connection failed: {}", response.status()));
        }
        
        info!("✅ Server connection successful");
        Ok(())
    }

    async fn download_all_files(&mut self) -> Result<()> {
        let url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}", 
                         self.metadata.server_url, self.metadata.client_id);
        
        info!("🔍 Requesting files from: {}", url);
        
        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Could not connect to server: {}", e);
                return Ok(());
            }
        };
        
        if !response.status().is_success() {
            warn!("Server returned error: {}", response.status());
            return Ok(());
        }
        
        // First, get the raw text to debug
        let response_text = response.text().await?;
        info!("📋 Raw server response: {}", response_text);
        
        // Parse the JSON - handle both array and object responses
        let server_files: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(files) => files,
            Err(e) => {
                error!("Failed to parse JSON response: {}", e);
                error!("Response was: {}", response_text);
                
                // Try parsing as a wrapper object
                if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&response_text) {
                    if let Some(files_array) = wrapper.get("files") {
                        if let Some(files) = files_array.as_array() {
                            files.clone()
                        } else {
                            return Err(anyhow::anyhow!("Server response 'files' field is not an array"));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Server response does not contain 'files' field"));
                    }
                } else {
                    return Err(anyhow::anyhow!("Could not parse server response as JSON"));
                }
            }
        };
        
        info!("📁 Found {} files on server", server_files.len());
        
        for file_info in server_files {
            if let Some(name) = file_info["name"].as_str() {
                if file_info["is_file"].as_bool() == Some(true) && !name.starts_with('.') {
                    let local_path = self.sync_folder.join(name);
                    
                    let should_download = if local_path.exists() {
                        // Check if sizes differ
                        if let Ok(local_metadata) = fs::metadata(&local_path).await {
                            if let Some(server_size) = file_info["size"].as_u64() {
                                local_metadata.len() != server_size
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    } else {
                        true
                    };
                    
                    if should_download {
                        info!("📥 Downloading: {}", name);
                        if let Err(e) = self.download_file(name).await {
                            error!("Failed to download {}: {}", name, e);
                        } else {
                            info!("✅ Downloaded: {}", name);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn download_file(&mut self, filename: &str) -> Result<()> {
        let download_url = format!("{}/api/download/{}?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                  self.metadata.server_url, 
                                  urlencoding::encode(filename),
                                  self.metadata.client_id);
        
        let response = self.http_client.get(&download_url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Download failed: {}", response.status()));
        }
        
        let encrypted_data = response.bytes().await?;
        
        // Try to decrypt - if it fails, assume it's not encrypted
        let decrypted_data = match self.encryptor.decrypt(&encrypted_data) {
            Ok(data) => data,
            Err(_) => {
                warn!("Could not decrypt {}, assuming unencrypted", filename);
                encrypted_data.to_vec()
            }
        };
        
        let local_path = self.sync_folder.join(filename);
        
        // Create parent directories if needed
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(&local_path, &decrypted_data).await?;
        
        // Update metadata
        let file_record = FileRecord {
            path: filename.to_string(),
            size: decrypted_data.len() as u64,
            modified: Utc::now(),
            checksum: calculate_checksum(&decrypted_data),
            encrypted: false,
        };
        
        self.metadata.update_file_record(file_record);
        
        Ok(())
    }

    async fn upload_local_files(&mut self) -> Result<()> {
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
                        info!("📤 Uploading: {}", path_str);
                        if let Err(e) = self.upload_file(&path_str).await {
                            error!("Failed to upload {}: {}", path_str, e);
                        } else {
                            info!("✅ Uploaded: {}", path_str);
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
        // Simple deletion handling - remove local files that no longer exist on server
        let url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}", 
                         self.metadata.server_url, self.metadata.client_id);
        
        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => resp,
            Err(_) => return Ok(()), // Skip if server unavailable
        };
        
        let response_text = response.text().await?;
        let server_files: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(files) => files,
            Err(_) => return Ok(()), // Skip on parse error
        };
        
        let mut server_file_names = std::collections::HashSet::new();
        
        for file_info in server_files {
            if let Some(name) = file_info["name"].as_str() {
                if file_info["is_file"].as_bool() == Some(true) {
                    server_file_names.insert(name.to_string());
                }
            }
        }
        
        // Check local files and remove ones not on server
        let mut files_to_delete = Vec::new();
        
        for entry in WalkDir::new(&self.sync_folder) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.starts_with('.') {
                        continue;
                    }
                    
                    let relative_path = entry.path().strip_prefix(&self.sync_folder)?;
                    let filename_str = relative_path.to_string_lossy().to_string();
                    
                    // Only delete if we have this file in our metadata (meaning we got it from server)
                    if self.metadata.get_file_record(&filename_str).is_some() && 
                       !server_file_names.contains(&filename_str) {
                        files_to_delete.push((entry.path().to_path_buf(), filename_str));
                    }
                }
            }
        }
        
        for (local_path, filename) in files_to_delete {
            match fs::remove_file(&local_path).await {
                Ok(_) => {
                    info!("🗑️ Deleted local file (removed from server): {}", filename);
                    self.metadata.remove_file_record(&filename);
                }
                Err(e) => {
                    error!("Failed to delete local file {}: {}", filename, e);
                }
            }
        }
        
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
