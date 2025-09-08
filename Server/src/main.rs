mod config;
mod server;
mod auth;
mod admin;
mod folder_scanner;
mod web_admin;

use std::thread;
use std::net::TcpListener;
use crate::server::handle_client;
use crate::web_admin::start_admin_server;
use crate::config::{load_server_config, save_server_config, MacPermission};

fn ensure_admin_exists() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_server_config("server_config.json")?;
    
    // Get server MAC address
    let server_mac = get_server_mac_address();
    
    // Check if any admin exists
    let has_admin = config.mac_permissions.values().any(|p| p.is_admin);
    
    if !has_admin {
        println!("⚠️ No admin found! Adding server MAC as admin: {}", server_mac);
        
        let admin_permission = MacPermission {
            mac_address: server_mac.clone(),
            username: "Server Admin".to_string(),
            allowed_folders: config.available_folders.clone(),
            can_read_files: true,
            is_admin: true,
        };
        
        config.mac_permissions.insert(server_mac.clone(), admin_permission);
        save_server_config("server_config.json", &config)?;
        
        println!("✅ Server MAC {} added as admin successfully!", server_mac);
    } else {
        println!("✅ Admin user found in config");
    }
    
    Ok(())
}

fn get_server_mac_address() -> String {
    use std::process::Command;
    
    #[cfg(target_os = "linux")]
    {
        let interfaces = ["eno1", "eth0", "wlo1", "wlan0"];
        for interface in &interfaces {
            let path = format!("/sys/class/net/{}/address", interface);
            if let Ok(output) = Command::new("cat").arg(&path).output() {
                if output.status.success() {
                    let mac = String::from_utf8(output.stdout).unwrap_or_default().trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }
    }
    "00:11:22:33:44:55".to_string()
}

fn main() {
    println!("🚀 Starting Secure Data Vault Server");
    
    // Ensure admin exists before starting services
    if let Err(e) = ensure_admin_exists() {
        eprintln!("Failed to ensure admin exists: {}", e);
    }
    
    // Start TCP server for client connections
    thread::spawn(|| {
        println!("📡 Starting TCP server on 192.168.1.2:7878");
        let listener = TcpListener::bind("192.168.1.2:7878")
            .expect("Failed to bind to 192.168.1.2:7878");
        
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        handle_client(stream);
                    });
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        }
    });
    
    // Start web admin interface
    println!("👑 Starting Admin Web Interface on 192.168.1.2:8080");
    if let Err(e) = start_admin_server() {
        eprintln!("Failed to start admin server: {}", e);
    }
}
