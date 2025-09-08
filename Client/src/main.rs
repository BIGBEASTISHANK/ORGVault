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

// Enhanced MAC address detection for all platforms
fn get_mac_address() -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        // Method 1: Try getmac command
        if let Ok(output) = Command::new("getmac")
            .arg("/fo")
            .arg("csv")
            .arg("/nh") // No header
            .output() 
        {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if let Some(mac_part) = line.split(',').next() {
                        let mac = mac_part.trim_matches('"').trim();
                        if !mac.is_empty() && mac != "N/A" && mac.len() >= 17 {
                            let formatted_mac = mac.replace("-", ":").to_lowercase();
                            println!("🔍 Detected MAC (Windows getmac): {}", formatted_mac);
                            return Ok(formatted_mac);
                        }
                    }
                }
            }
        }
        
        // Method 2: Try PowerShell as fallback
        if let Ok(output) = Command::new("powershell")
            .arg("-Command")
            .arg("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty MacAddress")
            .output()
        {
            if output.status.success() {
                let mac = String::from_utf8(output.stdout)?.trim().replace("-", ":").to_lowercase();
                if !mac.is_empty() && mac.len() >= 17 {
                    println!("🔍 Detected MAC (Windows PowerShell): {}", mac);
                    return Ok(mac);
                }
            }
        }
        
        // Method 3: Try wmic as another fallback
        if let Ok(output) = Command::new("wmic")
            .arg("path")
            .arg("win32_networkadapter")
            .arg("where")
            .arg("index=0")
            .arg("get")
            .arg("macaddress")
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    let line = line.trim();
                    if line.len() >= 17 && line.contains(":") {
                        println!("🔍 Detected MAC (Windows wmic): {}", line);
                        return Ok(line.to_lowercase());
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        // Method 1: Try primary ethernet interfaces
        let interfaces = ["eth0", "eno1", "enp0s3", "enp3s0", "enp4s0"];
        for interface in &interfaces {
            let path = format!("/sys/class/net/{}/address", interface);
            if let Ok(output) = Command::new("cat").arg(&path).output() {
                if output.status.success() {
                    let mac = String::from_utf8(output.stdout)?.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        println!("🔍 Detected MAC (Linux {}): {}", interface, mac);
                        return Ok(mac);
                    }
                }
            }
        }
        
        // Method 2: Try wireless interfaces
        let wifi_interfaces = ["wlan0", "wlo1", "wlp2s0", "wlp3s0"];
        for interface in &wifi_interfaces {
            let path = format!("/sys/class/net/{}/address", interface);
            if let Ok(output) = Command::new("cat").arg(&path).output() {
                if output.status.success() {
                    let mac = String::from_utf8(output.stdout)?.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        println!("🔍 Detected MAC (Linux WiFi {}): {}", interface, mac);
                        return Ok(mac);
                    }
                }
            }
        }
        
        // Method 3: Try ip link command
        if let Ok(output) = Command::new("ip").arg("link").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("link/ether") && !line.contains("00:00:00:00:00:00") {
                        if let Some(mac_part) = line.split_whitespace().nth(1) {
                            println!("🔍 Detected MAC (Linux ip link): {}", mac_part);
                            return Ok(mac_part.to_string());
                        }
                    }
                }
            }
        }
        
        // Method 4: Try ifconfig as fallback
        if let Ok(output) = Command::new("ifconfig").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("ether") || line.contains("HWaddr") {
                        for part in line.split_whitespace() {
                            if part.len() == 17 && part.matches(':').count() == 5 {
                                if part != "00:00:00:00:00:00" {
                                    println!("🔍 Detected MAC (Linux ifconfig): {}", part);
                                    return Ok(part.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        // Method 1: Try ifconfig for en0 (primary ethernet)
        if let Ok(output) = Command::new("ifconfig").arg("en0").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("ether") {
                        if let Some(mac) = line.split_whitespace().nth(1) {
                            println!("🔍 Detected MAC (macOS en0): {}", mac);
                            return Ok(mac.to_string());
                        }
                    }
                }
            }
        }
        
        // Method 2: Try en1 (often WiFi)
        if let Ok(output) = Command::new("ifconfig").arg("en1").output() {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("ether") {
                        if let Some(mac) = line.split_whitespace().nth(1) {
                            println!("🔍 Detected MAC (macOS en1): {}", mac);
                            return Ok(mac.to_string());
                        }
                    }
                }
            }
        }
        
        // Method 3: Try system_profiler
        if let Ok(output) = Command::new("system_profiler")
            .arg("SPNetworkDataType")
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8(output.stdout)?;
                for line in output_str.lines() {
                    if line.contains("MAC Address:") || line.contains("Ethernet Address:") {
                        if let Some(mac_part) = line.split(':').nth(1) {
                            let mac = mac_part.trim();
                            if mac.len() >= 17 {
                                println!("🔍 Detected MAC (macOS system_profiler): {}", mac);
                                return Ok(mac.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Final fallback - return default test MAC
    println!("⚠️ Could not detect MAC address, using fallback");
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
    println!("📡 Requesting folder structure from server...");
    
    let mac_address = match get_mac_address() {
        Ok(mac) => {
            println!("🔍 Client MAC address: {}", mac);
            mac
        }
        Err(e) => {
            eprintln!("❌ Failed to get MAC address: {}", e);
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
            eprintln!("❌ Failed to connect to server: {}", e);
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
    
    // Display detected MAC address at startup
    match get_mac_address() {
        Ok(mac) => println!("🔍 Detected Client MAC Address: {}", mac),
        Err(e) => eprintln!("⚠️ Could not detect MAC address: {}", e),
    }
    
    // Try to open browser automatically
    if let Err(e) = open::that("http://localhost:3000") {
        eprintln!("⚠️ Could not auto-open browser: {}", e);
        println!("🌐 Please open http://localhost:3000 manually");
    } else {
        println!("🌐 Opening browser at http://localhost:3000");
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
