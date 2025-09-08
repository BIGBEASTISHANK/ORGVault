use crate::auth::{get_user_permissions, is_admin_mac};
use actix_files::Files;
use actix_multipart::Multipart;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Result};
use chrono::Utc;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

// Define missing query parameter structs
#[derive(Deserialize)]
struct FileListQuery {
    folder: String,
    mac: String,
}

#[derive(Deserialize)]
struct FileDownloadQuery {
    folder: String,
    mac: String,
}

#[derive(Deserialize)]
struct FileUploadQuery {
    folder: String,
    mac: String,
}

// Enhanced file info structure with checksums
#[derive(Serialize)]
struct EnhancedFileInfo {
    name: String,
    path: String,
    size: u64,
    modified: String,
    is_file: bool,
    checksum: Option<String>,
}

#[derive(Deserialize)]
struct FileDeleteRequest {
    file_path: String,
    mac: String,
}

#[derive(Deserialize)]
struct FileRenameRequest {
    old_path: String,
    new_path: String,
    mac: String,
}

#[derive(Deserialize)]
struct MacRequest {
    mac_address: String,
    username: String,
    allowed_folders: Vec<String>,
    can_read_files: bool,
    is_admin: bool,
}

#[derive(Deserialize)]
struct RemoveMacRequest {
    mac_address: String,
}

// Implement missing check_folder_permission function with detailed logging
fn check_folder_permission(mac_address: &str, folder_path: &str) -> Result<bool, std::io::Error> {
    println!("\n┌─────────────── PERMISSION CHECK ───────────────┐");
    println!("│ 🔐 MAC: {:<40} │", mac_address);
    println!("│ 📁 Folder: {:<37} │", folder_path);
    println!("└─────────────────────────────────────────────────┘");

    match get_user_permissions(mac_address) {
        Ok(permission) => {
            println!("📋 USER PERMISSIONS:");
            println!("   👤 Username: {}", permission.username);
            println!(
                "   👑 Admin: {}",
                if permission.is_admin { "YES" } else { "NO" }
            );
            println!("   📁 Allowed folders: {:?}", permission.allowed_folders);
            println!();

            if permission.is_admin {
                println!("👑 ADMIN ACCESS GRANTED: Full access to folder");
                Ok(true)
            } else {
                println!("🔍 CHECKING FOLDER ACCESS:");
                let has_permission = permission.allowed_folders.iter().any(|allowed| {
                    let matches =
                        folder_path.starts_with(allowed) || allowed.starts_with(folder_path);
                    println!(
                        "   '{}' vs '{}' -> {}",
                        folder_path,
                        allowed,
                        if matches { "✅ MATCH" } else { "❌ NO MATCH" }
                    );
                    matches
                });

                if has_permission {
                    println!("✅ USER ACCESS GRANTED");
                } else {
                    println!("❌ USER ACCESS DENIED");
                }

                Ok(has_permission)
            }
        }
        Err(e) => {
            println!("❌ PERMISSION CHECK FAILED: {}", e);
            Ok(false)
        }
    }
}

fn get_server_mac_address() -> String {
    use std::process::Command;

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("cat")
            .arg("/sys/class/net/eno1/address")
            .output()
        {
            if output.status.success() {
                if let Ok(mac) = String::from_utf8(output.stdout) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        println!("🖥️ SERVER MAC DETECTED: {}", mac);
                        return mac;
                    }
                }
            }
        }
    }
    println!("🖥️ SERVER MAC FALLBACK: Using default");
    "00:11:22:33:44:55".to_string()
}

#[get("/api/server-info")]
async fn get_server_info() -> Result<HttpResponse> {
    println!("🌐 API CALL: GET /api/server-info");
    let server_mac = get_server_mac_address();
    let timestamp = Utc::now().to_rfc3339();

    println!(
        "✅ SERVER INFO RESPONSE: mac={}, time={}",
        server_mac, timestamp
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_mac": server_mac,
        "timestamp": timestamp
    })))
}

#[get("/api/folders")]
async fn get_available_folders() -> Result<HttpResponse> {
    println!("🌐 API CALL: GET /api/folders");

    match crate::config::load_server_config("server_config.json") {
        Ok(config) => {
            println!(
                "✅ AVAILABLE FOLDERS: {} folders found",
                config.available_folders.len()
            );
            for (i, folder) in config.available_folders.iter().enumerate() {
                println!("   {}. {}", i + 1, folder);
            }
            Ok(HttpResponse::Ok().json(&config.available_folders))
        }
        Err(e) => {
            println!("❌ FOLDERS ERROR: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load config: {}", e)
            })))
        }
    }
}

#[get("/api/macs")]
async fn get_mac_permissions() -> Result<HttpResponse> {
    println!("🌐 API CALL: GET /api/macs");

    match crate::config::load_server_config("server_config.json") {
        Ok(config) => {
            println!(
                "✅ MAC PERMISSIONS: {} MACs configured",
                config.mac_permissions.len()
            );
            for (mac, perm) in &config.mac_permissions {
                println!(
                    "   📱 {}: {} (admin: {}, folders: {})",
                    mac,
                    perm.username,
                    perm.is_admin,
                    perm.allowed_folders.len()
                );
            }
            Ok(HttpResponse::Ok().json(&config.mac_permissions))
        }
        Err(e) => {
            println!("❌ MAC PERMISSIONS ERROR: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load config: {}", e)
            })))
        }
    }
}

#[post("/api/mac/add")]
async fn add_mac_permission(mac_req: web::Json<MacRequest>) -> Result<HttpResponse> {
    println!("🌐 API CALL: POST /api/mac/add");
    let server_mac = get_server_mac_address();
    let req_data = mac_req.into_inner();

    println!(
        "📝 ADD MAC REQUEST: mac={}, username={}, admin={}, folders={:?}",
        req_data.mac_address, req_data.username, req_data.is_admin, req_data.allowed_folders
    );

    let folders_str = req_data.allowed_folders.join(",");
    let command = format!(
        "admin_add_mac|||{}|||{}|||{}|||{}|||{}",
        req_data.mac_address,
        req_data.username,
        folders_str,
        req_data.can_read_files,
        req_data.is_admin
    );

    println!("🔧 EXECUTING ADMIN COMMAND: {}", command);
    let result = crate::admin::handle_admin_command(&server_mac, &command);
    println!("📤 ADD MAC RESULT: {}", result);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/mac/remove")]
async fn remove_mac_permission(mac_req: web::Json<RemoveMacRequest>) -> Result<HttpResponse> {
    println!("🌐 API CALL: POST /api/mac/remove");
    let server_mac = get_server_mac_address();

    println!("🗑️ REMOVE MAC REQUEST: {}", mac_req.mac_address);

    let command = format!("admin_remove_mac|||{}", mac_req.mac_address);
    println!("🔧 EXECUTING ADMIN COMMAND: {}", command);

    let result = crate::admin::handle_admin_command(&server_mac, &command);
    println!("📤 REMOVE MAC RESULT: {}", result);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/scan")]
async fn trigger_scan() -> Result<HttpResponse> {
    println!("🌐 API CALL: POST /api/scan");
    println!("🔍 STARTING FOLDER SCAN: /home/ishank/ORGCenterFolder");

    match crate::folder_scanner::scan_and_save_org_folders(
        "/home/ishank/ORGCenterFolder",
        "server_config.json",
    ) {
        Ok(_) => {
            println!("✅ FOLDER SCAN COMPLETED SUCCESSFULLY");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "✅ Folder scan completed successfully"
            })))
        }
        Err(e) => {
            println!("❌ FOLDER SCAN FAILED: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Scan failed: {}", e)
            })))
        }
    }
}

// Enhanced file listing with metadata
#[get("/api/files")]
async fn list_files_enhanced(query: web::Query<FileListQuery>) -> Result<HttpResponse> {
    let folder_path = &query.folder;
    let mac_address = &query.mac;
    let timestamp = Utc::now().to_rfc3339();

    println!("\n═══════════════════════════════════════════");
    println!("🌐 API CALL: GET /api/files");
    println!("📂 FILE LIST REQUEST:");
    println!("   📁 Folder: '{}'", folder_path);
    println!("   🆔 MAC: '{}'", mac_address);
    println!("   🕐 Time: {}", timestamp);
    println!("═══════════════════════════════════════════");

    // Special case: if requesting root org folder, return user's allowed subfolders
    if folder_path == "/home/ishank/ORGCenterFolder" {
        return get_user_allowed_folders(mac_address).await;
    }

    match check_folder_permission(mac_address, folder_path) {
        Ok(true) => {
            println!("✅ PERMISSION GRANTED: Proceeding with file listing\n");
        }
        Ok(false) => {
            println!(
                "❌ PERMISSION DENIED: Access forbidden for {}\n",
                mac_address
            );
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied to this folder"
            })));
        }
        Err(e) => {
            println!("❌ PERMISSION CHECK ERROR: {}\n", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Permission check failed: {}", e)
            })));
        }
    }

    let mut files = Vec::new();

    println!("📁 SCANNING DIRECTORY: {}", folder_path);
    println!("─────────────────────────────────────────");

    match fs::read_dir(folder_path) {
        Ok(entries) => {
            let mut file_count = 0;
            let mut folder_count = 0;

            for entry in entries {
                if let Ok(entry) = entry {
                    if let Ok(metadata) = entry.metadata() {
                        let file_path = entry.path();
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let is_file = metadata.is_file();
                        let size = if is_file { metadata.len() } else { 0 };

                        println!(
                            "📄 FOUND: {} ({}), size: {} bytes",
                            file_name,
                            if is_file { "FILE" } else { "FOLDER" },
                            size
                        );

                        if is_file {
                            file_count += 1;
                        } else {
                            folder_count += 1;
                        }

                        let checksum = if is_file {
                            match fs::read(&file_path) {
                                Ok(data) => {
                                    let hash = calculate_file_checksum(&data);
                                    println!("   🔐 Checksum: {}", hash);
                                    Some(hash)
                                }
                                Err(e) => {
                                    println!("   ❌ Checksum error: {}", e);
                                    None
                                }
                            }
                        } else {
                            None
                        };

                        let file_info = EnhancedFileInfo {
                            name: file_name,
                            path: entry.path().to_string_lossy().to_string(),
                            size,
                            modified: format!(
                                "{:?}",
                                metadata
                                    .modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                            ),
                            is_file,
                            checksum,
                        };
                        files.push(file_info);

                        if is_file {
                            println!(); // Extra space after each file
                        }
                    }
                }
            }

            println!("─────────────────────────────────────────");
            println!("📊 DIRECTORY SUMMARY:");
            println!("   📄 Files: {}", file_count);
            println!("   📁 Folders: {}", folder_count);
            println!("   📦 Total items: {}", files.len());
            println!("─────────────────────────────────────────");
        }
        Err(e) => {
            println!("❌ DIRECTORY READ ERROR: {}", e);
            println!("═══════════════════════════════════════════\n");
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read directory: {}", e)
            })));
        }
    }

    println!("📤 SENDING FILE LIST: {} items", files.len());
    println!("═══════════════════════════════════════════\n");

    Ok(HttpResponse::Ok().json(files))
}

// Helper function to get user's allowed folders
async fn get_user_allowed_folders(mac_address: &str) -> Result<HttpResponse> {
    println!("🔍 GETTING ALLOWED FOLDERS FOR MAC: {}", mac_address);

    match get_user_permissions(mac_address) {
        Ok(permissions) => {
            let mut allowed_folders = Vec::new();

            if permissions.is_admin {
                println!("👑 ADMIN ACCESS: Returning all folders");
                // Admin sees all folders in ORGCenterFolder
                if let Ok(entries) = fs::read_dir("/home/ishank/ORGCenterFolder") {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            if entry.path().is_dir() {
                                let folder_name = entry.file_name().to_string_lossy().to_string();
                                allowed_folders.push(EnhancedFileInfo {
                                    name: folder_name.clone(),
                                    path: entry.path().to_string_lossy().to_string(),
                                    size: 0,
                                    modified: "".to_string(),
                                    is_file: false,
                                    checksum: None,
                                });
                                println!("   📁 Added folder: {}", folder_name);
                            }
                        }
                    }
                }
            } else {
                println!("👤 USER ACCESS: Filtering by permissions");
                // Regular user sees only their allowed folders
                for allowed_path in &permissions.allowed_folders {
                    let path = Path::new(allowed_path);
                    if path.exists() && path.is_dir() {
                        if let Some(folder_name) = path.file_name() {
                            let folder_name_str = folder_name.to_string_lossy().to_string();
                            allowed_folders.push(EnhancedFileInfo {
                                name: folder_name_str.clone(),
                                path: allowed_path.clone(),
                                size: 0,
                                modified: "".to_string(),
                                is_file: false,
                                checksum: None,
                            });
                            println!("   📁 Added allowed folder: {}", folder_name_str);
                        }
                    }
                }
            }

            println!("✅ RETURNING {} ALLOWED FOLDERS", allowed_folders.len());
            Ok(HttpResponse::Ok().json(allowed_folders))
        }
        Err(e) => {
            println!("❌ PERMISSION ERROR: {}", e);
            Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })))
        }
    }
}

#[get("/api/download/{filename:.*}")]
async fn download_file(
    path: web::Path<String>,
    query: web::Query<FileDownloadQuery>,
) -> Result<HttpResponse> {
    let filename = path.into_inner();
    let mac_address = &query.mac;
    let folder = &query.folder;
    let timestamp = Utc::now().to_rfc3339();

    println!("\n╔═══════════════════════════════════════════╗");
    println!("║              📥 DOWNLOAD REQUEST           ║");
    println!("╠═══════════════════════════════════════════╣");
    println!("║ File: {:<35} ║", filename);
    println!("║ MAC:  {:<35} ║", mac_address);
    println!("║ Time: {:<35} ║", timestamp);
    println!("╚═══════════════════════════════════════════╝");

    let file_path = PathBuf::from(folder).join(&filename);
    println!("🔍 Full path: {:?}", file_path);
    println!();

    match check_folder_permission(mac_address, folder) {
        Ok(true) => {
            println!("✅ DOWNLOAD PERMISSION GRANTED\n");
        }
        Ok(false) => {
            println!("❌ DOWNLOAD PERMISSION DENIED\n");
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })));
        }
        Err(e) => {
            println!("❌ DOWNLOAD PERMISSION ERROR: {}\n", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }

    match fs::read(&file_path) {
        Ok(contents) => {
            println!("✅ FILE READ SUCCESSFUL:");
            println!("   📊 Size: {} bytes", contents.len());
            println!("   📁 Path: {:?}", file_path);
            println!("╚═══════════════════════════════════════════╝\n");

            Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                ))
                .body(contents))
        }
        Err(e) => {
            println!("❌ FILE READ ERROR: {}", e);
            println!("╚═══════════════════════════════════════════╝\n");

            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("File not found: {}", e)
            })))
        }
    }
}

#[post("/api/upload")]
async fn upload_file_enhanced(
    mut payload: Multipart,
    query: web::Query<FileUploadQuery>,
) -> Result<HttpResponse> {
    let mac_address = &query.mac;
    let folder = &query.folder;
    let timestamp = Utc::now().to_rfc3339();

    println!("\n╔═══════════════════════════════════════════╗");
    println!("║              📤 UPLOAD REQUEST             ║");
    println!("╠═══════════════════════════════════════════╣");
    println!("║ MAC:    {:<35} ║", mac_address);
    println!("║ Folder: {:<35} ║", folder);
    println!("║ Time:   {:<35} ║", timestamp);
    println!("╚═══════════════════════════════════════════╝");

    match check_folder_permission(mac_address, folder) {
        Ok(true) => {
            println!("✅ UPLOAD PERMISSION GRANTED\n");
        }
        Ok(false) => {
            println!("❌ UPLOAD PERMISSION DENIED\n");
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied to upload to this folder"
            })));
        }
        Err(e) => {
            println!("❌ UPLOAD PERMISSION ERROR: {}\n", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }

    while let Some(field_result) = payload.next().await {
        let mut field = field_result?; // Fixed: proper error handling

        let content_disposition = field.content_disposition().clone();
        let filename = if let Some(name) = content_disposition.get_filename() {
            name.to_string()
        } else {
            println!("❌ UPLOAD ERROR: No filename provided\n");
            println!("╚═══════════════════════════════════════════╝\n");
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No filename provided"
            })));
        };

        println!("📝 PROCESSING UPLOAD:");
        println!("   📄 Filename: {}", filename);

        let file_path = PathBuf::from(folder).join(&filename);
        println!("   🔍 Target path: {:?}", file_path);

        // Create parent directories if needed
        if let Some(parent) = file_path.parent() {
            match fs::create_dir_all(parent) {
                Ok(_) => println!("   📁 Directory ensured: {:?}", parent),
                Err(e) => {
                    println!("   ❌ Directory creation failed: {}", e);
                    println!("╚═══════════════════════════════════════════╝\n");
                    return Err(actix_web::error::ErrorInternalServerError(format!(
                        "Cannot create directory: {}",
                        e
                    )));
                }
            }
        }

        // Create the file
        let mut file = match fs::File::create(&file_path) {
            Ok(f) => {
                println!("   ✅ File created successfully");
                f
            }
            Err(e) => {
                println!("   ❌ File creation failed: {}", e);
                println!("╚═══════════════════════════════════════════╝\n");
                return Err(actix_web::error::ErrorInternalServerError(format!(
                    "Cannot create file: {}",
                    e
                )));
            }
        };

        println!("\n📊 UPLOAD PROGRESS:");
        println!("─────────────────────────────────────────");

        let mut total_size = 0u64;
        let mut chunk_count = 0;

        // Process file chunks
        while let Some(chunk_result) = field.next().await {
            let data = chunk_result?;
            chunk_count += 1;
            total_size += data.len() as u64;

            match file.write_all(&data) {
                Ok(_) => {
                    if chunk_count % 10 == 0 {
                        // Log every 10 chunks to avoid spam
                        println!(
                            "   📦 Chunk {}: {} bytes (total: {} bytes)",
                            chunk_count,
                            data.len(),
                            total_size
                        );
                    }
                }
                Err(e) => {
                    println!("   ❌ Write failed at chunk {}: {}", chunk_count, e);
                    println!("╚═══════════════════════════════════════════╝\n");
                    return Err(actix_web::error::ErrorInternalServerError(format!(
                        "Cannot write to file: {}",
                        e
                    )));
                }
            }
        }

        println!("─────────────────────────────────────────");
        println!("📈 UPLOAD STATISTICS:");
        println!("   📦 Total chunks: {}", chunk_count);
        println!(
            "   📊 Total size: {} bytes ({:.2} KB)",
            total_size,
            total_size as f64 / 1024.0
        );

        // Calculate checksum
        let file_data = match fs::read(&file_path) {
            Ok(data) => {
                println!("   ✅ File verification: {} bytes read", data.len());
                data
            }
            Err(e) => {
                println!("   ❌ File verification failed: {}", e);
                println!("╚═══════════════════════════════════════════╝\n");
                return Err(actix_web::error::ErrorInternalServerError(format!(
                    "Cannot read uploaded file: {}",
                    e
                )));
            }
        };

        let checksum = calculate_file_checksum(&file_data);
        println!("   🔐 Checksum: {}", checksum);

        println!("\n✅ UPLOAD COMPLETED SUCCESSFULLY:");
        println!("   📁 File: {}", filename);
        println!("   📊 Size: {} bytes", total_size);
        println!("   🔐 Checksum: {}", checksum);
        println!("   🆔 MAC: {}", mac_address);
        println!("   🕐 Completed: {}", Utc::now().to_rfc3339());
        println!("╚═══════════════════════════════════════════╝\n");

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": format!("File {} uploaded successfully", filename),
            "filename": filename,
            "size": total_size,
            "checksum": checksum,
            "mac": mac_address,
            "timestamp": Utc::now().to_rfc3339(),
            "success": true
        })));
    }

    println!("❌ UPLOAD ERROR: No file found in request");
    println!("╚═══════════════════════════════════════════╝\n");

    Ok(HttpResponse::BadRequest().json(serde_json::json!({
        "error": "No file found in request",
        "success": false
    })))
}

#[post("/api/delete")]
async fn delete_file_from_server(req: web::Json<FileDeleteRequest>) -> Result<HttpResponse> {
    let file_path = &req.file_path;
    let mac_address = &req.mac;
    let timestamp = Utc::now().to_rfc3339();

    println!("🌐 API CALL: POST /api/delete");
    println!(
        "🗑️ DELETE REQUEST: file='{}', mac='{}', time={}",
        file_path, mac_address, timestamp
    );

    match check_folder_permission(mac_address, "/home/ishank/ORGCenterFolder") {
        Ok(true) => {
            println!("✅ DELETE PERMISSION GRANTED");
        }
        Ok(false) => {
            println!("❌ DELETE PERMISSION DENIED");
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })));
        }
        Err(e) => {
            println!("❌ DELETE PERMISSION ERROR: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }

    let full_path = PathBuf::from("/home/ishank/ORGCenterFolder").join(file_path);
    println!("🔍 DELETE PATH: {:?}", full_path);

    match fs::remove_file(&full_path) {
        Ok(_) => {
            println!("✅ FILE DELETED SUCCESSFULLY: {}", file_path);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": format!("File {} deleted successfully", file_path),
                "success": true
            })))
        }
        Err(e) => {
            println!("❌ FILE DELETION FAILED: {} -> {}", file_path, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete file: {}", e),
                "success": false
            })))
        }
    }
}

#[post("/api/rename")]
async fn rename_file_on_server(req: web::Json<FileRenameRequest>) -> Result<HttpResponse> {
    let old_path = &req.old_path;
    let new_path = &req.new_path;
    let mac_address = &req.mac;
    let timestamp = Utc::now().to_rfc3339();

    println!("🌐 API CALL: POST /api/rename");
    println!(
        "🔄 RENAME REQUEST: '{}' -> '{}', mac='{}', time={}",
        old_path, new_path, mac_address, timestamp
    );

    match check_folder_permission(mac_address, "/home/ishank/ORGCenterFolder") {
        Ok(true) => {
            println!("✅ RENAME PERMISSION GRANTED");
        }
        Ok(false) => {
            println!("❌ RENAME PERMISSION DENIED");
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })));
        }
        Err(e) => {
            println!("❌ RENAME PERMISSION ERROR: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }

    let old_full_path = PathBuf::from("/home/ishank/ORGCenterFolder").join(old_path);
    let new_full_path = PathBuf::from("/home/ishank/ORGCenterFolder").join(new_path);

    println!(
        "🔍 RENAME PATHS: '{:?}' -> '{:?}'",
        old_full_path, new_full_path
    );

    match fs::rename(&old_full_path, &new_full_path) {
        Ok(_) => {
            println!("✅ FILE RENAMED SUCCESSFULLY: {} -> {}", old_path, new_path);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": format!("File renamed from {} to {}", old_path, new_path),
                "success": true
            })))
        }
        Err(e) => {
            println!("❌ FILE RENAME FAILED: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to rename file: {}", e),
                "success": false
            })))
        }
    }
}

// Helper function for calculating checksums
fn calculate_file_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// Start the enhanced admin server
pub fn start_admin_server() -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    rt.block_on(async {
        println!("🚀 STARTING ENHANCED ADMIN WEB INTERFACE");
        
        // AUTO-SCAN folders on startup
        println!("🔍 PERFORMING STARTUP FOLDER SCAN...");
        if let Err(e) = crate::folder_scanner::scan_and_save_org_folders("/home/ishank/ORGCenterFolder", "server_config.json") {
            println!("❌ Startup scan failed: {}", e);
        } else {
            println!("✅ Startup scan completed");
        }
        
        println!("🌐 Server URL: http://192.168.1.2:8080");
        println!("📅 Start Time: {}", Utc::now().to_rfc3339());

        HttpServer::new(|| {
            println!("🔧 INITIALIZING HTTP SERVER");
            App::new()
                .service(get_server_info)
                .service(get_available_folders)
                .service(get_mac_permissions)
                .service(add_mac_permission)
                .service(remove_mac_permission)
                .service(trigger_scan)
                .service(list_files_enhanced)
                .service(download_file)
                .service(upload_file_enhanced)
                .service(delete_file_from_server)
                .service(rename_file_on_server)
                .service(Files::new("/", "static").index_file("admin.html"))
        })
        .bind("192.168.1.2:8080")?
        .run()
        .await
    })
}

#[post("/api/admin/rescan")]
async fn trigger_rescan() -> Result<HttpResponse> {
    println!("🔄 ADMIN: Triggering folder rescan...");

    match crate::folder_scanner::scan_and_save_org_folders(
        "/home/ishank/ORGCenterFolder",
        "server_config.json",
    ) {
        Ok(_) => {
            println!("✅ ADMIN: Folder rescan completed");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Folder scan completed successfully",
                "success": true
            })))
        }
        Err(e) => {
            println!("❌ ADMIN: Folder rescan failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Scan failed: {}", e),
                "success": false
            })))
        }
    }
}
