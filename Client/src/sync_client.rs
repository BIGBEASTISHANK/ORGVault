use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::Mutex;
use tokio::fs;
use tokio::time::{interval, Duration};
use chrono::Utc;
use walkdir::WalkDir;
use anyhow::Result;
use log::{info, warn, error, debug};
use sha2::{Sha256, Digest};
use notify::{Watcher, RecursiveMode, EventKind, event::{CreateKind, ModifyKind, RemoveKind}};
use std::sync::mpsc;

use crate::metadata::{SyncMetadata, FileRecord};
use crate::encryption::Encryptor;

pub struct SyncClient {
    sync_folder: PathBuf,
    metadata_file: PathBuf,
    metadata: SyncMetadata,
    encryptor: Encryptor,
    client: reqwest::Client,
    watcher: Option<notify::RecommendedWatcher>,
    is_syncing: Arc<Mutex<bool>>,
}

impl SyncClient {
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
        let client = reqwest::Client::new();
        
        info!("🔄 Sync client initialized");
        info!("📁 Sync folder: {:?}", sync_folder);
        info!("🌐 Server URL: {}", metadata.server_url);
        info!("🆔 Client ID: {}", metadata.client_id);
        
        Ok(Self {
            sync_folder,
            metadata_file,
            metadata,
            encryptor,
            client,
            watcher: None,
            is_syncing: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn start_sync(&mut self) -> Result<()> {
        info!("🚀 Starting real-time file synchronization");
        
        self.initial_sync().await?;
        self.start_real_time_watcher().await?;
        self.start_periodic_sync().await?;
        
        info!("✅ Real-time sync started successfully");
        Ok(())
    }

    async fn start_real_time_watcher(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(tx)?;
        watcher.watch(&self.sync_folder, RecursiveMode::Recursive)?;
        
        self.watcher = Some(watcher);
        
        let sync_folder = self.sync_folder.clone();
        let metadata_file = self.metadata_file.clone();
        let server_url = self.metadata.server_url.clone();
        let client_id = self.metadata.client_id.clone();
        let encryption_key = self.metadata.encryption_key.clone().unwrap();
        let is_syncing = self.is_syncing.clone();
        
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let encryptor = Encryptor::new(&encryption_key);
            
            info!("👁️ Real-time file watcher started for: {:?}", sync_folder);
            
            loop {
                match rx.recv() {
                    Ok(Ok(event)) => {
                        if *is_syncing.lock().await {
                            continue;
                        }
                        
                        match event.kind {
                            EventKind::Create(CreateKind::File) |
                            EventKind::Modify(ModifyKind::Data(_)) => {
                                for path in &event.paths {
                                    if Self::should_sync_file(path, &sync_folder) {
                                        if let Some(relative_path) = path.strip_prefix(&sync_folder).ok() {
                                            info!("📝 File changed detected: {:?} - Uploading immediately", relative_path);
                                            
                                            if let Err(e) = Self::upload_file_immediately(
                                                &client,
                                                &encryptor,
                                                &sync_folder,
                                                &metadata_file,
                                                &server_url,
                                                &client_id,
                                                relative_path
                                            ).await {
                                                error!("Failed to upload file {:?}: {}", relative_path, e);
                                            } else {
                                                info!("✅ File uploaded immediately: {:?}", relative_path);
                                            }
                                        }
                                    }
                                }
                            }
                            EventKind::Remove(RemoveKind::File) => {
                                for path in &event.paths {
                                    if let Some(relative_path) = path.strip_prefix(&sync_folder).ok() {
                                        // Skip metadata files
                                        if let Some(filename) = relative_path.file_name() {
                                            if let Some(name_str) = filename.to_str() {
                                                if name_str.starts_with('.') {
                                                    continue;
                                                }
                                            }
                                        }
                                        
                                        info!("🗑️ File deletion detected: {:?} - Notifying server immediately", relative_path);
                                        
                                        if let Err(e) = Self::delete_file_on_server(
                                            &client,
                                            &metadata_file,
                                            &server_url,
                                            &client_id,
                                            relative_path,
                                        ).await {
                                            error!("Failed to delete file on server: {}", e);
                                        } else {
                                            info!("✅ File deletion sent to server: {:?}", relative_path);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(e)) => error!("File watch error: {:?}", e),
                    Err(e) => {
                        error!("File watcher channel error: {:?}", e);
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }

    fn should_sync_file(path: &Path, sync_folder: &Path) -> bool {
        if let Some(filename) = path.file_name() {
            if let Some(name_str) = filename.to_str() {
                if name_str.starts_with('.') {
                    return false;
                }
            }
        }
        path.starts_with(sync_folder) && path.is_file()
    }

    async fn upload_file_immediately(
        client: &reqwest::Client,
        encryptor: &Encryptor,
        sync_folder: &Path,
        metadata_file: &Path,
        server_url: &str,
        client_id: &str,
        relative_path: &Path,
    ) -> Result<()> {
        let local_path = sync_folder.join(relative_path);
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let file_data = match fs::read(&local_path).await {
            Ok(data) => data,
            Err(e) => {
                warn!("Could not read file {:?}: {}", local_path, e);
                return Ok(());
            }
        };
        
        let encrypted_data = encryptor.encrypt(&file_data)?;
        
        let upload_url = format!("{}/api/upload?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                server_url, client_id);
        
        let filename = relative_path.to_string_lossy();
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(encrypted_data)
                .file_name(filename.to_string()));
        
        let response = client.post(&upload_url).multipart(form).send().await?;
        
        if response.status().is_success() {
            let mut metadata = SyncMetadata::load_from(metadata_file)?;
            let file_record = FileRecord {
                path: filename.to_string(),
                size: file_data.len() as u64,
                modified: Utc::now(),
                checksum: Self::calculate_checksum(&file_data),
                encrypted: false,
            };
            
            metadata.update_file_record(file_record);
            metadata.save_to(metadata_file)?;
            
            info!("📤 Real-time upload successful: {}", filename);
        } else {
            error!("Upload failed with status: {}", response.status());
        }
        
        Ok(())
    }

    // **FIXED**: Proper deletion notification to server
    async fn delete_file_on_server(
        client: &reqwest::Client,
        metadata_file: &Path,
        server_url: &str,
        client_id: &str,
        relative_path: &Path,
    ) -> Result<()> {
        let filename = relative_path.to_string_lossy();
        
        // Remove from local metadata first
        let mut metadata = SyncMetadata::load_from(metadata_file)?;
        metadata.remove_file_record(&filename);
        metadata.save_to(metadata_file)?;
        
        // Send DELETE request to server with proper JSON body
        let delete_url = format!("{}/api/delete", server_url);
        
        let delete_body = serde_json::json!({
            "file_path": filename.to_string(),
            "mac": client_id
        });
        
        let response = client.post(&delete_url)
            .json(&delete_body)
            .send()
            .await?;
        
        if response.status().is_success() {
            info!("🗑️ File deletion confirmed by server: {}", filename);
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Failed to delete file on server: {} - {}", status, body);
            return Err(anyhow::anyhow!("Server delete failed: {}", status));
        }
        
        Ok(())
    }

    async fn start_periodic_sync(&mut self) -> Result<()> {
        let sync_folder = self.sync_folder.clone();
        let metadata_file = self.metadata_file.clone();
        let server_url = self.metadata.server_url.clone();
        let client_id = self.metadata.client_id.clone();
        let encryption_key = self.metadata.encryption_key.clone().unwrap();
        let is_syncing = self.is_syncing.clone();
        
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let encryptor = Encryptor::new(&encryption_key);
            let mut interval = interval(Duration::from_secs(5)); // Faster sync for deletions
            
            info!("⏰ Started periodic sync every 5 seconds");
            
            loop {
                interval.tick().await;
                
                *is_syncing.lock().await = true;
                
                if let Err(e) = Self::download_server_changes(
                    &client,
                    &encryptor,
                    &sync_folder,
                    &metadata_file,
                    &server_url,
                    &client_id,
                ).await {
                    error!("Periodic sync failed: {}", e);
                }
                
                *is_syncing.lock().await = false;
                
                debug!("🔄 Periodic sync completed");
            }
        });
        
        Ok(())
    }

    async fn download_server_changes(
        client: &reqwest::Client,
        encryptor: &Encryptor,
        sync_folder: &Path,
        metadata_file: &Path,
        server_url: &str,
        client_id: &str,
    ) -> Result<()> {
        let url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}", 
                         server_url, client_id);
        
        let response = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Could not connect to server for sync: {}", e);
                return Ok(());
            }
        };
        
        let server_files: Vec<serde_json::Value> = response.json().await?;
        let mut metadata = SyncMetadata::load_from(metadata_file)?;
        
        // Track server files for deletion detection
        let mut server_file_names = HashSet::new();
        
        // Process downloads/updates
        for file_info in &server_files {
            if let Some(name) = file_info["name"].as_str() {
                if file_info["is_file"].as_bool() == Some(true) {
                    server_file_names.insert(name.to_string());
                    
                    let local_path = sync_folder.join(name);
                    let should_download = if local_path.exists() {
                        if let Some(local_record) = metadata.get_file_record(name) {
                            if let Some(server_size) = file_info["size"].as_u64() {
                                local_record.size != server_size
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
                        info!("📥 Downloading updated file from server: {}", name);
                        
                        if let Err(e) = Self::download_file_from_server_static(
                            client,
                            encryptor,
                            sync_folder,
                            metadata_file,
                            server_url,
                            client_id,
                            name,
                        ).await {
                            error!("Failed to download {}: {}", name, e);
                        } else {
                            info!("✅ Downloaded and decrypted: {}", name);
                        }
                    }
                }
            }
        }
        
        // **Handle deletions from server** - Only delete if file was on server before
        let mut files_to_delete = Vec::new();
        
        for entry in WalkDir::new(sync_folder) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    // Skip metadata files
                    if filename.starts_with('.') {
                        continue;
                    }
                    
                    let relative_path = entry.path().strip_prefix(sync_folder)?;
                    let filename_str = relative_path.to_string_lossy().to_string();
                    
                    // Only delete if file was tracked in our metadata (meaning it came from server)
                    if let Some(_record) = metadata.get_file_record(&filename_str) {
                        if !server_file_names.contains(&filename_str) {
                            files_to_delete.push((entry.path().to_path_buf(), filename_str));
                        }
                    }
                }
            }
        }
        
        // Delete files that no longer exist on server
        for (local_path, filename) in files_to_delete {
            match fs::remove_file(&local_path).await {
                Ok(_) => {
                    info!("🗑️ Deleted local file (removed from server): {}", filename);
                    
                    // Remove from metadata
                    let mut metadata = SyncMetadata::load_from(metadata_file)?;
                    metadata.remove_file_record(&filename);
                    metadata.save_to(metadata_file)?;
                    
                    println!("📥 Server deletion synced: {}", filename);
                }
                Err(e) => {
                    error!("Failed to delete local file {}: {}", filename, e);
                }
            }
        }
        
        Ok(())
    }

    async fn download_file_from_server_static(
        client: &reqwest::Client,
        encryptor: &Encryptor,
        sync_folder: &Path,
        metadata_file: &Path,
        server_url: &str,
        client_id: &str,
        filename: &str,
    ) -> Result<()> {
        let download_url = format!("{}/api/download/{}?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                  server_url, 
                                  urlencoding::encode(filename),
                                  client_id);
        
        let response = client.get(&download_url).send().await?;
        let encrypted_data = response.bytes().await?;
        
        let decrypted_data = encryptor.decrypt(&encrypted_data)?;
        
        let local_path = sync_folder.join(filename);
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(&local_path, &decrypted_data).await?;
        
        let mut metadata = SyncMetadata::load_from(metadata_file)?;
        let file_record = FileRecord {
            path: filename.to_string(),
            size: decrypted_data.len() as u64,
            modified: Utc::now(),
            checksum: Self::calculate_checksum(&decrypted_data),
            encrypted: false,
        };
        
        metadata.update_file_record(file_record);
        metadata.save_to(metadata_file)?;
        
        Ok(())
    }

    pub async fn initial_sync(&mut self) -> Result<()> {
        info!("🔄 Starting initial sync");
        
        *self.is_syncing.lock().await = true;
        
        match self.download_all_files().await {
            Ok(count) => info!("📥 Downloaded {} files from server", count),
            Err(e) => warn!("Failed to download files: {}", e),
        }
        
        match self.upload_local_files().await {
            Ok(count) => info!("📤 Uploaded {} local files", count),
            Err(e) => warn!("Failed to upload files: {}", e),
        }
        
        self.metadata.last_sync = Some(Utc::now());
        self.metadata.save_to(&self.metadata_file)?;
        
        *self.is_syncing.lock().await = false;
        
        info!("✅ Initial sync completed");
        Ok(())
    }

    async fn download_all_files(&mut self) -> Result<usize> {
        let url = format!("{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}", 
                         self.metadata.server_url, self.metadata.client_id);
        
        let response = self.client.get(&url).send().await?;
        let server_files: Vec<serde_json::Value> = response.json().await?;
        
        let mut downloaded = 0;
        
        for file_info in server_files {
            if let Some(name) = file_info["name"].as_str() {
                if file_info["is_file"].as_bool() == Some(true) {
                    match self.download_file_from_server(name).await {
                        Ok(_) => {
                            downloaded += 1;
                            info!("📥 Downloaded: {}", name);
                        }
                        Err(e) => error!("Failed to download {}: {}", name, e),
                    }
                }
            }
        }
        
        Ok(downloaded)
    }

    async fn download_file_from_server(&mut self, filename: &str) -> Result<()> {
        let download_url = format!("{}/api/download/{}?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                  self.metadata.server_url, 
                                  urlencoding::encode(filename),
                                  self.metadata.client_id);
        
        let response = self.client.get(&download_url).send().await?;
        let encrypted_data = response.bytes().await?;
        
        let decrypted_data = self.encryptor.decrypt(&encrypted_data)?;
        
        let local_path = self.sync_folder.join(filename);
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(&local_path, &decrypted_data).await?;
        
        let file_record = FileRecord {
            path: filename.to_string(),
            size: decrypted_data.len() as u64,
            modified: Utc::now(),
            checksum: Self::calculate_checksum(&decrypted_data),
            encrypted: false,
        };
        
        self.metadata.update_file_record(file_record);
        self.metadata.save_to(&self.metadata_file)?;
        
        Ok(())
    }

    async fn upload_local_files(&mut self) -> Result<usize> {
        let mut uploaded = 0;
        
        for entry in WalkDir::new(&self.sync_folder) {
            let entry = entry?;
            if entry.file_type().is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.starts_with('.') {
                        continue;
                    }
                    
                    let relative_path = entry.path().strip_prefix(&self.sync_folder)?;
                    match self.upload_file(relative_path).await {
                        Ok(_) => {
                            uploaded += 1;
                            debug!("📤 Uploaded: {:?}", relative_path);
                        }
                        Err(e) => error!("Failed to upload {:?}: {}", relative_path, e),
                    }
                }
            }
        }
        
        Ok(uploaded)
    }

    pub async fn upload_file(&mut self, relative_path: &Path) -> Result<()> {
        let local_path = self.sync_folder.join(relative_path);
        let file_data = fs::read(&local_path).await?;
        
        let encrypted_data = self.encryptor.encrypt(&file_data)?;
        
        let upload_url = format!("{}/api/upload?folder=/home/ishank/ORGCenterFolder&mac={}", 
                                self.metadata.server_url, self.metadata.client_id);
        
        let filename = relative_path.to_string_lossy();
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(encrypted_data)
                .file_name(filename.to_string()));
        
        let response = self.client.post(&upload_url).multipart(form).send().await?;
        
        if response.status().is_success() {
            let file_record = FileRecord {
                path: filename.to_string(),
                size: file_data.len() as u64,
                modified: Utc::now(),
                checksum: Self::calculate_checksum(&file_data),
                encrypted: false,
            };
            
            self.metadata.update_file_record(file_record);
            self.metadata.save_to(&self.metadata_file)?;
            
            info!("📤 Uploaded: {}", filename);
        } else {
            return Err(anyhow::anyhow!("Upload failed with status: {}", response.status()));
        }
        
        Ok(())
    }

    fn calculate_checksum(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
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
    
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("getmac").arg("/fo").arg("csv").arg("/nh").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                if let Some(line) = output_str.lines().next() {
                    if let Some(mac) = line.split(',').next() {
                        let mac = mac.trim_matches('"').replace("-", ":");
                        return Ok(mac.to_lowercase());
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ifconfig").arg("en0").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("ether") {
                        if let Some(mac) = line.split_whitespace().nth(1) {
                            return Ok(mac.to_string());
                        }
                    }
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Could not detect MAC address"))
}
