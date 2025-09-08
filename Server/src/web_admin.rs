use actix_web::{get, post, web, App, HttpServer, HttpResponse, Result};
use actix_files::Files;
use actix_multipart::Multipart;
use serde::{Deserialize, Serialize};
use futures_util::StreamExt as _;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::config::load_server_config;
use crate::admin::handle_admin_command;
use crate::folder_scanner::scan_and_save_org_folders;
use std::process::Command;

#[derive(Deserialize, Debug)]
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

#[derive(Serialize)]
struct FileInfo {
    name: String,
    path: String,
    size: u64,
    modified: String,
    is_file: bool,
}

fn get_server_mac_address() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("cat").arg("/sys/class/net/eno1/address").output() {
            if output.status.success() {
                if let Ok(mac) = String::from_utf8(output.stdout) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }
        
        if let Ok(output) = Command::new("cat").arg("/sys/class/net/wlo1/address").output() {
            if output.status.success() {
                if let Ok(mac) = String::from_utf8(output.stdout) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }
    }
    
    "00:11:22:33:44:55".to_string()
}

fn check_folder_permission(mac_address: &str, folder_path: &str) -> Result<bool, std::io::Error> {
    let config = load_server_config("server_config.json")?;
    
    if let Some(permission) = config.mac_permissions.get(mac_address) {
        let has_permission = permission.allowed_folders.iter().any(|allowed| {
            folder_path.starts_with(allowed) || allowed.starts_with(folder_path)
        });
        Ok(has_permission)
    } else {
        Ok(false)
    }
}

#[get("/api/server-info")]
async fn get_server_info() -> Result<HttpResponse> {
    let server_mac = get_server_mac_address();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_mac": server_mac,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

#[get("/api/folders")]
async fn get_available_folders() -> Result<HttpResponse> {
    match load_server_config("server_config.json") {
        Ok(config) => Ok(HttpResponse::Ok().json(&config.available_folders)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to load config: {}", e)
        })))
    }
}

#[get("/api/macs")]
async fn get_mac_permissions() -> Result<HttpResponse> {
    match load_server_config("server_config.json") {
        Ok(config) => Ok(HttpResponse::Ok().json(&config.mac_permissions)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to load config: {}", e)
        })))
    }
}

#[post("/api/mac/add")]
async fn add_mac_permission(mac_req: web::Json<MacRequest>) -> Result<HttpResponse> {
    let server_mac = get_server_mac_address();
    let req_data = mac_req.into_inner();
    
    let folders_str = req_data.allowed_folders.join(",");
    let command = format!(
        "admin_add_mac|||{}|||{}|||{}|||{}|||{}",
        req_data.mac_address,
        req_data.username,
        folders_str,
        req_data.can_read_files,
        req_data.is_admin
    );
    
    let result = handle_admin_command(&server_mac, &command);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/mac/remove")]
async fn remove_mac_permission(mac_req: web::Json<RemoveMacRequest>) -> Result<HttpResponse> {
    let server_mac = get_server_mac_address();
    let command = format!("admin_remove_mac|||{}", mac_req.mac_address);
    let result = handle_admin_command(&server_mac, &command);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/scan")]
async fn trigger_scan() -> Result<HttpResponse> {
    match scan_and_save_org_folders("/home/ishank/ORGCenterFolder", "server_config.json") {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "✅ Folder scan completed successfully"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Scan failed: {}", e)
        })))
    }
}

#[get("/api/files")]
async fn list_files(query: web::Query<FileListQuery>) -> Result<HttpResponse> {
    let folder_path = &query.folder;
    let mac_address = &query.mac;
    
    match check_folder_permission(mac_address, folder_path) {
        Ok(true) => {},
        Ok(false) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied to this folder"
            })));
        },
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Permission check failed: {}", e)
            })));
        }
    }
    
    let mut files = Vec::new();
    
    match fs::read_dir(folder_path) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Ok(metadata) = entry.metadata() {
                        let file_info = FileInfo {
                            name: entry.file_name().to_string_lossy().to_string(),
                            path: entry.path().to_string_lossy().to_string(),
                            size: if metadata.is_file() { metadata.len() } else { 0 },
                            modified: format!("{:?}", metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                            is_file: metadata.is_file(),
                        };
                        files.push(file_info);
                    }
                }
            }
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read directory: {}", e)
            })));
        }
    }
    
    Ok(HttpResponse::Ok().json(files))
}

#[get("/api/download/{filename:.*}")]
async fn download_file(
    path: web::Path<String>,
    query: web::Query<FileDownloadQuery>
) -> Result<HttpResponse> {
    let filename = path.into_inner();
    let mac_address = &query.mac;
    let folder = &query.folder;
    
    let file_path = PathBuf::from(folder).join(&filename);
    
    match check_folder_permission(mac_address, folder) {
        Ok(true) => {},
        Ok(false) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })));
        },
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }
    
    match fs::read(&file_path) {
        Ok(contents) => {
            Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(contents))
        }
        Err(e) => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("File not found: {}", e)
            })))
        }
    }
}

#[post("/api/upload")]
async fn upload_file(
    mut payload: Multipart,
    query: web::Query<FileUploadQuery>
) -> Result<HttpResponse> {
    let mac_address = &query.mac;
    let folder = &query.folder;
    
    match check_folder_permission(mac_address, folder) {
        Ok(true) => {},
        Ok(false) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied to upload to this folder"
            })));
        },
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Permission check failed"
            })));
        }
    }
    
    while let Some(mut field) = payload.next().await {
        let field = field?;
        
        // Clone the content disposition to avoid borrow conflicts
        let content_disposition = field.content_disposition().clone();
        let filename = if let Some(name) = content_disposition.get_filename() {
            name.to_string() // Clone to owned String
        } else {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No filename provided"
            })));
        };
        
        let file_path = PathBuf::from(folder).join(&filename);
        
        let mut file = fs::File::create(&file_path)
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Cannot create file: {}", e)))?;
        
        // Now we can use field mutably without borrow conflicts
        let mut field = field;
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            file.write_all(&data)
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Cannot write to file: {}", e)))?;
        }
        
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": format!("File {} uploaded successfully", filename)
        })));
    }
    
    Ok(HttpResponse::BadRequest().json(serde_json::json!({
        "error": "No file found in request"
    })))
}

pub fn start_admin_server() -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    rt.block_on(async {
        println!("👑 Starting Admin Web Interface on 192.168.1.2:8080");
        
        HttpServer::new(|| {
            App::new()
                .service(get_server_info)
                .service(get_available_folders)
                .service(get_mac_permissions)
                .service(add_mac_permission)
                .service(remove_mac_permission)
                .service(trigger_scan)
                .service(list_files)
                .service(download_file)
                .service(upload_file)
                .service(Files::new("/", "static").index_file("admin.html"))
        })
        .bind("192.168.1.2:8080")?
        .run()
        .await
    })
}
