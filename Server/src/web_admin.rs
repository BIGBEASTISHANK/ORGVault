use actix_web::{get, post, web, App, HttpServer, HttpResponse, Result};
use actix_files::Files;
use serde::Deserialize;
use crate::config::load_server_config;
use crate::admin::handle_admin_command;
use crate::folder_scanner::scan_and_save_org_folders;
use std::process::Command;

#[derive(Deserialize, Debug)]
struct MacRequest {
    mac_address: String,
    username: String,
    allowed_folders: Vec<String>,
    can_read_files: bool,  // Note: field name matches JSON exactly
    is_admin: bool,
}

#[derive(Deserialize)]
struct RemoveMacRequest {
    mac_address: String,
}

fn get_server_mac_address() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("cat").arg("/sys/class/net/eno1/address").output() {
            if output.status.success() {
                if let Ok(mac) = String::from_utf8(output.stdout) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        println!("🔍 Server MAC (eno1): {}", mac);
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
                        println!("🔍 Server MAC (wlo1): {}", mac);
                        return mac;
                    }
                }
            }
        }
    }
    
    println!("⚠️  Using fallback MAC address");
    "00:11:22:33:44:55".to_string()
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
    
    // Debug print to see what we received
    println!("🔍 Received MAC request:");
    println!("  MAC: {}", req_data.mac_address);
    println!("  Username: {}", req_data.username);
    println!("  Folders: {:?}", req_data.allowed_folders);
    println!("  Can Read: {}", req_data.can_read_files);
    println!("  Is Admin: {}", req_data.is_admin);
    
    // Validate MAC address format
    if req_data.mac_address.len() != 17 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "message": format!("❌ Invalid MAC address format. Expected 17 characters, got {}", req_data.mac_address.len())
        })));
    }
    
    let folders_str = req_data.allowed_folders.join(",");
    
    // Use ||| as delimiter to avoid conflicts with MAC address colons
    let command = format!(
        "admin_add_mac|||{}|||{}|||{}|||{}|||{}",
        req_data.mac_address,
        req_data.username,
        folders_str,
        req_data.can_read_files,
        req_data.is_admin
    );
    
    println!("🔧 Executing command: {}", command);
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
                .service(Files::new("/", "static").index_file("admin.html"))
        })
        .bind("192.168.1.2:8080")?
        .run()
        .await
    })
}
