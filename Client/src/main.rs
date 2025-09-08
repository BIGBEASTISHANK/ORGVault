use actix_web::{get, web, App, HttpServer, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;
use std::process::Command;
use actix_files::Files;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FolderEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: Option<u64>,
    modified: Option<String>,
    children: Option<Vec<FolderEntry>>,
    content: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FileInfo {
    name: String,
    path: String,
    size: u64,
    modified: String,
    is_file: bool,
}

fn get_mac_address() -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let interfaces = ["eth0", "eno1", "enp0s3", "enp3s0", "enp4s0"];
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
        
        let wifi_interfaces = ["wlan0", "wlo1", "wlp2s0", "wlp3s0"];
        for interface in &wifi_interfaces {
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
    
    Ok("00:11:22:33:44:55".to_string())
}

fn send_command_to_server(command: &str) -> Result<String, std::io::Error> {
    let mut stream = TcpStream::connect("192.168.1.2:7878")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    
    stream.write_all(command.as_bytes())?;
    
    let mut buffer = vec![0; 16384];
    let bytes_read = stream.read(&mut buffer)?;
    
    Ok(String::from_utf8_lossy(&buffer[0..bytes_read]).to_string())
}

#[get("/api/folders")]
async fn get_folders() -> Result<HttpResponse> {
    let mac_address = match get_mac_address() {
        Ok(mac) => mac,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to detect MAC address",
                "details": e.to_string()
            })));
        }
    };
    
    let auth_command = format!("auth:{}", mac_address);
    match send_command_to_server(&auth_command) {
        Ok(response) => {
            if response.starts_with("❌") {
                Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied",
                    "message": response,
                    "mac_address": mac_address
                })))
            } else if let Ok(folder_structure) = serde_json::from_str::<FolderEntry>(&response) {
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "folder_structure": folder_structure,
                    "mac_address": mac_address,
                    "authenticated": true
                })))
            } else {
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "error": "Could not parse server response",
                    "response": response,
                    "mac_address": mac_address
                })))
            }
        }
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to vault server",
                "details": e.to_string()
            })))
        }
    }
}

#[get("/api/mac")]
async fn get_client_mac() -> Result<HttpResponse> {
    match get_mac_address() {
        Ok(mac) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "mac_address": mac,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to detect MAC address",
            "details": e.to_string()
        })))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting Secure Vault Client...");
    
    match get_mac_address() {
        Ok(mac) => println!("🔍 Detected Client MAC Address: {}", mac),
        Err(e) => eprintln!("⚠️ Could not detect MAC address: {}", e),
    }
    
    if let Err(e) = open::that("http://localhost:3000") {
        eprintln!("⚠️ Could not auto-open browser: {}", e);
        println!("🌐 Please open http://localhost:3000 manually");
    }
    
    println!("🔗 Client will authenticate using MAC address");
    println!("📡 Starting web server on localhost:3000...");
    
    HttpServer::new(|| {
        App::new()
            .service(get_folders)
            .service(get_client_mac)
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}
