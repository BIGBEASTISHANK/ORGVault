use crate::config::{load_server_config, count_items};
use crate::folder_scanner::scan_and_save_org_folders;
use crate::auth::handle_auth_request;
use crate::admin::handle_admin_command;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

lazy_static::lazy_static! {
    static ref CONNECTED_CLIENTS: Arc<Mutex<HashMap<String, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub fn handle_client(mut stream: TcpStream) {
    let peer_addr = stream.peer_addr().unwrap();
    println!("🔗 New client connected: {}", peer_addr);
    
    let mut buffer = [0; 8192];
    let mut client_mac = String::new();
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("❌ Client {} disconnected", peer_addr);
                if !client_mac.is_empty() {
                    let mut clients = CONNECTED_CLIENTS.lock().unwrap();
                    clients.remove(&client_mac);
                }
                break;
            }
            Ok(n) => {
                let received = String::from_utf8_lossy(&buffer[0..n]);
                let command = received.trim();
                println!("📨 Received from {}: {}", peer_addr, command);
                
                let response = if command.starts_with("sync_register:") {
                    let mac_address = &command[14..];
                    client_mac = mac_address.to_string();
                    
                    {
                        let mut clients = CONNECTED_CLIENTS.lock().unwrap();
                        clients.insert(client_mac.clone(), stream.try_clone().unwrap());
                    }
                    
                    match load_server_config("server_config.json") {
                        Ok(config) => {
                            if let Some(permission) = config.mac_permissions.get(mac_address) {
                                let accessible_folders = if permission.is_admin {
                                    config.available_folders.clone()
                                } else {
                                    permission.allowed_folders.clone()
                                };
                                
                                serde_json::json!({
                                    "status": "registered",
                                    "encryption_key": config.encryption_key,
                                    "allowed_folders": accessible_folders,
                                    "folder_structure": config.folder_structure,
                                    "is_admin": permission.is_admin
                                }).to_string()
                            } else {
                                "❌ Unauthorized MAC address".to_string()
                            }
                        }
                        Err(e) => format!("❌ Config error: {}", e)
                    }
                } else if command.starts_with("auth:") {
                    let mac_address = &command[5..];
                    handle_auth_request(mac_address)
                } else if command.starts_with("admin:") {
                    let parts: Vec<&str> = command[6..].splitn(2, ':').collect();
                    if parts.len() == 2 {
                        handle_admin_command(parts[0], parts[1])
                    } else {
                        "❌ Invalid admin command format".to_string()
                    }
                } else {
                    match command {
                        "scan" => {
                            match scan_and_save_org_folders("/home/ishank/ORGCenterFolder", "server_config.json") {
                                Ok(_) => {
                                    notify_all_clients("folder_structure_updated");
                                    "✅ Folder scan completed successfully".to_string()
                                }
                                Err(e) => format!("❌ Scan failed: {}", e),
                            }
                        }
                        "status" => {
                            match load_server_config("server_config.json") {
                                Ok(config) => {
                                    let (folders, files) = count_items(&config.folder_structure);
                                    let clients = CONNECTED_CLIENTS.lock().unwrap();
                                    format!("📊 Status: {} folders, {} files. {} MAC permissions. {} connected clients. Last scan: {}", 
                                           folders, files, config.mac_permissions.len(), clients.len(), config.last_scan)
                                }
                                Err(_) => "❌ No configuration found. Run 'scan' first.".to_string(),
                            }
                        }
                        _ => format!("🤖 Unknown command: {}. Available: auth:MAC, scan, status", command),
                    }
                };
                
                if let Err(e) = stream.write_all(response.as_bytes()) {
                    eprintln!("❌ Failed to send response to {}: {}", peer_addr, e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to receive data from {}: {}", peer_addr, e);
                break;
            }
        }
    }
}

fn notify_all_clients(message: &str) {
    let clients = CONNECTED_CLIENTS.lock().unwrap();
    for (mac, mut stream) in clients.iter() {
        if let Err(e) = stream.write_all(message.as_bytes()) {
            eprintln!("Failed to notify client {}: {}", mac, e);
        }
    }
}
