use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::fs;
use tokio::time::{interval, Duration};
use walkdir::WalkDir;

use crate::encryption::Encryptor;
use crate::metadata::{calculate_checksum, FileRecord, SyncMetadata};

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
        println!("🚀 Starting bidirectional file synchronization");

        // Test server connection first
        if let Err(e) = self.test_server_connection().await {
            println!("❌ Server connection test failed: {}", e);
            return Err(e);
        }

        // Initial sync - download everything from server
        self.download_all_files().await?;

        // Upload any local files
        self.upload_local_files().await?;

        // Handle bidirectional deletions
        self.handle_deletions().await?;

        // Start continuous sync loop
        let mut sync_interval = interval(Duration::from_secs(30));

        loop {
            sync_interval.tick().await;

            println!("\n🔄 Running sync cycle...");

            // Download new/changed files from server
            if let Err(e) = self.download_all_files().await {
                println!("❌ Download sync failed: {}", e);
            }

            // Upload any new local files
            if let Err(e) = self.upload_local_files().await {
                println!("❌ Upload sync failed: {}", e);
            }

            // Handle bidirectional deletions
            if let Err(e) = self.handle_deletions().await {
                println!("❌ Deletion sync failed: {}", e);
            }

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
        let status = response.status(); // Get status first

        if status == 401 {
            // Handle unauthorized error with MAC info
            let error_body = response.text().await?; // Now consume response
            if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_body) {
                if let Some(mac) = error_json["mac_address"].as_str() {
                    println!("\n╔═══════════════════════════════════════════╗");
                    println!("║           ❌ ACCESS DENIED                 ║");
                    println!("╠═══════════════════════════════════════════╣");
                    println!("║ Your device is not registered with server ║");
                    println!("║                                           ║");
                    println!("║ 🆔 Your MAC Address: {:<19} ║", mac);
                    println!("║                                           ║");
                    println!("║ 📬 PLEASE CONTACT YOUR ADMINISTRATOR     ║");
                    println!("║ and provide them with your MAC address   ║");
                    println!("║ shown above so they can add your device  ║");
                    println!("║ to the server's allowed devices list.    ║");
                    println!("╚═══════════════════════════════════════════╝\n");

                    if let Some(help) = error_json["help"].as_str() {
                        println!("💡 {}", help);
                    }

                    return Err(anyhow::anyhow!("Device not registered. MAC: {}", mac));
                }
            }
        }

        if !status.is_success() {
            println!("❌ Server connection failed: {}", status);
            return Err(anyhow::anyhow!("Server connection failed: {}", status));
        }

        println!("✅ Server connection successful");
        Ok(())
    }

    async fn download_all_files(&mut self) -> Result<()> {
        let url = format!(
            "{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}",
            self.metadata.server_url, self.metadata.client_id
        );

        println!("🔍 Requesting root folder from: {}", url);

        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("❌ Could not connect to server: {}", e);
                return Ok(());
            }
        };

        let status = response.status(); // Store status before consuming response
        let response_text = response.text().await?; // Consume response ONCE here

        // Now handle different status codes using the stored status and response_text
        if status == 401 {
            // Handle unauthorized MAC address error
            if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                println!("\n╔═══════════════════════════════════════════╗");
                println!("║           🚫 UNAUTHORIZED ACCESS          ║");
                println!("╠═══════════════════════════════════════════╣");

                if let Some(mac) = error_json["mac_address"].as_str() {
                    println!("║ Your MAC Address: {:<23} ║", mac);
                    println!("║                                           ║");
                    println!("║ 📞 Contact your administrator to add     ║");
                    println!("║ your device to the allowed list.         ║");
                }

                println!("╚═══════════════════════════════════════════╝\n");

                return Err(anyhow::anyhow!("Access denied - device not registered"));
            }
        }

        if !status.is_success() {
            println!("❌ Server returned error: {}", status);
            return Ok(());
        }

        // For success case, use the already consumed response_text
        println!("📋 Server response length: {} chars", response_text.len());

        let server_items: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(items) => {
                println!("✅ Successfully parsed JSON response");
                items
            }
            Err(e) => {
                println!("❌ Failed to parse JSON response: {}", e);
                println!("❌ Response was: {}", response_text);
                return Ok(());
            }
        };

        println!("📁 Found {} items in root folder", server_items.len());

        for (i, item) in server_items.iter().enumerate() {
            if let Some(name) = item["name"].as_str() {
                let is_file = item["is_file"].as_bool().unwrap_or(false);

                println!(
                    "📂 Processing item {}: {} (is_file: {})",
                    i + 1,
                    name,
                    is_file
                );

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
        let folder_url = format!(
            "{}/api/files?folder=/home/ishank/ORGCenterFolder/{}&mac={}",
            self.metadata.server_url,
            urlencoding::encode(folder_name),
            self.metadata.client_id
        );

        println!(
            "🔍 Exploring team folder: {} at {}",
            folder_name, folder_url
        );

        let response = match self.http_client.get(&folder_url).send().await {
            Ok(resp) => {
                println!("✅ Got folder response: {}", resp.status());
                resp
            }
            Err(e) => {
                println!("❌ Could not access folder {}: {}", folder_name, e);
                return Ok(());
            }
        };

        let status = response.status(); // Get status first

        if status == 401 {
            println!("❌ Unauthorized access to folder: {}", folder_name);
            return Ok(());
        }

        if !status.is_success() {
            println!("❌ Folder {} returned error: {}", folder_name, status);
            return Ok(());
        }

        let response_text = response.text().await?; // Now consume response
        println!(
            "📋 Folder '{}' response length: {} chars",
            folder_name,
            response_text.len()
        );

        let folder_items: Vec<serde_json::Value> = match serde_json::from_str(&response_text) {
            Ok(items) => {
                println!("✅ Successfully parsed folder JSON");
                items
            }
            Err(e) => {
                println!("❌ Failed to parse folder {} response: {}", folder_name, e);
                return Ok(());
            }
        };

        println!(
            "📁 Team folder '{}' contains {} items",
            folder_name,
            folder_items.len()
        );

        for (i, item) in folder_items.iter().enumerate() {
            if let Some(file_name) = item["name"].as_str() {
                let is_file = item["is_file"].as_bool().unwrap_or(false);

                println!(
                    "   📂 Processing folder item {}: {} (is_file: {})",
                    i + 1,
                    file_name,
                    is_file
                );

                if is_file && !file_name.starts_with('.') {
                    let relative_path = format!("{}/{}", folder_name, file_name);
                    let local_path = self.sync_folder.join(&relative_path);

                    println!("   📥 Found file to download: {}", relative_path);

                    // Check if file needs downloading
                    let should_download = if local_path.exists() {
                        if let Ok(local_metadata) = fs::metadata(&local_path).await {
                            if let Some(server_size) = item["size"].as_u64() {
                                let size_different = local_metadata.len() != server_size;
                                if size_different {
                                    println!(
                                        "   📊 Size difference for {}: local={}, server={}",
                                        relative_path,
                                        local_metadata.len(),
                                        server_size
                                    );
                                }
                                size_different
                            } else {
                                false
                            }
                        } else {
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
                    println!(
                        "   📁 Nested folder found: {}/{} (not implemented)",
                        folder_name, file_name
                    );
                }
            }
        }

        Ok(())
    }

    async fn download_file(&mut self, relative_path: &str) -> Result<()> {
        let download_url = format!(
            "{}/api/download/{}?folder=/home/ishank/ORGCenterFolder&mac={}",
            self.metadata.server_url,
            urlencoding::encode(relative_path),
            self.metadata.client_id
        );

        println!("   📥 Starting download: {}", relative_path);

        let response = self.http_client.get(&download_url).send().await?;
        let status = response.status(); // Get status first

        if status == 401 {
            println!("   ❌ Unauthorized access to file: {}", relative_path);
            return Err(anyhow::anyhow!("Unauthorized access to file"));
        }

        if !status.is_success() {
            println!(
                "   ❌ Download failed for {}: HTTP {}",
                relative_path, status
            );
            return Err(anyhow::anyhow!("Download failed: HTTP {}", status));
        }

        println!("   ✅ Download response OK for: {}", relative_path);

        let content = response.bytes().await?; // Use bytes() instead of text()
        println!(
            "   📦 Downloaded {} bytes for: {}",
            content.len(),
            relative_path
        );

        // Enhanced decryption with debugging
        let final_data = match self.encryptor.decrypt(&content) {
            Ok(decrypted) => {
                println!(
                    "   🔓 File decrypted successfully: {} -> {} bytes",
                    relative_path,
                    decrypted.len()
                );
                if decrypted.is_empty() {
                    println!("   ⚠️ WARNING: Decrypted data is empty! Using raw data instead");
                    content.to_vec()
                } else {
                    decrypted
                }
            }
            Err(e) => {
                println!(
                    "   📄 Decryption failed ({}), using raw data: {}",
                    e, relative_path
                );
                content.to_vec()
            }
        };

        println!("   📊 Final data size: {} bytes", final_data.len());

        let local_path = self.sync_folder.join(relative_path);

        // Create parent directories
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
            println!("   📁 Created directory structure: {:?}", parent);
        }

        // Write file to disk
        fs::write(&local_path, &final_data).await?;
        println!(
            "   💾 Saved file: {} ({} bytes)",
            relative_path,
            final_data.len()
        );

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
                    let needs_upload =
                        if let Some(record) = self.metadata.get_file_record(&path_str) {
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

        let upload_url = format!(
            "{}/api/upload?folder=/home/ishank/ORGCenterFolder&mac={}",
            self.metadata.server_url, self.metadata.client_id
        );

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(encrypted_data).file_name(relative_path.to_string()),
        );

        let response = self
            .http_client
            .post(&upload_url)
            .multipart(form)
            .send()
            .await?;
        let status = response.status(); // Get status first

        if status == 401 {
            println!("❌ Unauthorized upload for: {}", relative_path);
            return Err(anyhow::anyhow!("Unauthorized upload"));
        }

        if status.is_success() {
            let file_record = FileRecord {
                path: relative_path.to_string(),
                size: file_data.len() as u64,
                modified: Utc::now(),
                checksum: calculate_checksum(&file_data),
                encrypted: false,
            };

            self.metadata.update_file_record(file_record);
        } else {
            return Err(anyhow::anyhow!("Upload failed: {}", status));
        }

        Ok(())
    }

    async fn handle_deletions(&mut self) -> Result<()> {
        println!("🗑️ Starting bidirectional deletion check...");

        // Get complete server file structure
        let mut all_server_files = HashSet::new();
        if let Err(e) = self.collect_all_server_files(&mut all_server_files).await {
            println!("❌ Failed to collect server files: {}", e);
            return Ok(());
        }

        // Get all local files
        let mut all_local_files = HashSet::new();
        self.collect_all_local_files(&mut all_local_files);

        println!("📊 Deletion comparison:");
        println!("   📄 Server files: {}", all_server_files.len());
        for file in &all_server_files {
            println!("      📁 Server: {}", file);
        }
        println!("   📄 Local files: {}", all_local_files.len());
        for file in &all_local_files {
            println!("      💻 Local: {}", file);
        }

        // Handle server deletions (files that exist locally but not on server)
        let files_to_delete_locally: Vec<_> =
            all_local_files.difference(&all_server_files).collect();
        println!(
            "🗑️ Files to delete locally: {}",
            files_to_delete_locally.len()
        );
        for file_path in files_to_delete_locally {
            println!("   🗑️ Need to delete locally: {}", file_path);
            // Only delete if we have metadata (meaning we got it from server originally)
            if self.metadata.get_file_record(file_path).is_some() {
                let local_path = self.sync_folder.join(file_path);
                match fs::remove_file(&local_path).await {
                    Ok(_) => {
                        println!("✅ Deleted locally (removed from server): {}", file_path);
                        self.metadata.remove_file_record(file_path);
                    }
                    Err(e) => {
                        println!("❌ Failed to delete local file {}: {}", file_path, e);
                    }
                }
            } else {
                println!("   ⏭️ Skipping deletion (no metadata): {}", file_path);
            }
        }

        // Handle client deletions (files that exist on server but not locally)
        let files_to_delete_on_server: Vec<_> =
            all_server_files.difference(&all_local_files).collect();
        println!(
            "🗑️ Files to delete on server: {}",
            files_to_delete_on_server.len()
        );
        for file_path in files_to_delete_on_server {
            println!("   🗑️ Need to delete on server: {}", file_path);
            // Only delete from server if we have metadata (meaning we uploaded it)
            if self.metadata.get_file_record(file_path).is_some() {
                println!("   📤 Sending delete request to server for: {}", file_path);
                if let Err(e) = self.delete_file_on_server(file_path).await {
                    println!("   ❌ Failed to delete server file {}: {}", file_path, e);
                } else {
                    println!("   ✅ Deleted from server: {}", file_path);
                    self.metadata.remove_file_record(file_path);
                }
            } else {
                println!(
                    "   ⏭️ Skipping server deletion (no metadata): {}",
                    file_path
                );
            }
        }

        Ok(())
    }

    async fn collect_all_server_files(&self, server_files: &mut HashSet<String>) -> Result<()> {
        // Get root folder contents
        let url = format!(
            "{}/api/files?folder=/home/ishank/ORGCenterFolder&mac={}",
            self.metadata.server_url, self.metadata.client_id
        );

        let response = self.http_client.get(&url).send().await?;
        if !response.status().is_success() {
            return Ok(());
        }

        let response_text = response.text().await?;
        let root_items: Vec<serde_json::Value> = serde_json::from_str(&response_text)?;

        for item in root_items {
            if let Some(name) = item["name"].as_str() {
                let is_file = item["is_file"].as_bool().unwrap_or(false);

                if is_file {
                    server_files.insert(name.to_string());
                } else {
                    // Explore subfolder
                    if let Err(e) = self.collect_server_folder_files(name, server_files).await {
                        println!("❌ Failed to collect files from folder {}: {}", name, e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn collect_server_folder_files(
        &self,
        folder_name: &str,
        server_files: &mut HashSet<String>,
    ) -> Result<()> {
        let folder_url = format!(
            "{}/api/files?folder=/home/ishank/ORGCenterFolder/{}&mac={}",
            self.metadata.server_url,
            urlencoding::encode(folder_name),
            self.metadata.client_id
        );

        let response = self.http_client.get(&folder_url).send().await?;
        if !response.status().is_success() {
            return Ok(());
        }

        let response_text = response.text().await?;
        let folder_items: Vec<serde_json::Value> = serde_json::from_str(&response_text)?;

        for item in folder_items {
            if let Some(file_name) = item["name"].as_str() {
                if item["is_file"].as_bool() == Some(true) {
                    let relative_path = format!("{}/{}", folder_name, file_name);
                    server_files.insert(relative_path);
                }
            }
        }

        Ok(())
    }

    fn collect_all_local_files(&self, local_files: &mut HashSet<String>) {
        for entry in WalkDir::new(&self.sync_folder) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    if let Some(filename) = entry.file_name().to_str() {
                        if filename.starts_with('.') {
                            continue; // Skip hidden files
                        }

                        if let Ok(relative_path) = entry.path().strip_prefix(&self.sync_folder) {
                            let path_str = relative_path.to_string_lossy().to_string();
                            local_files.insert(path_str);
                        }
                    }
                }
            }
        }
    }

    async fn delete_file_on_server(&self, file_path: &str) -> Result<()> {
        let delete_url = format!("{}/api/delete-file", self.metadata.server_url);

        let delete_request = serde_json::json!({
            "file_path": file_path,
            "mac": self.metadata.client_id
        });

        let response = self
            .http_client
            .post(&delete_url)
            .json(&delete_request)
            .send()
            .await?;

        let status = response.status(); // Get status first

        if status == 401 {
            return Err(anyhow::anyhow!("Unauthorized delete request"));
        }

        if status.is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Server delete failed: {}", status))
        }
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
