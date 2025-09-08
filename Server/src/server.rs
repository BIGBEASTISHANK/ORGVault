use crate::config::{load_server_config, count_items};
use crate::folder_scanner::scan_and_save_org_folders;
use crate::auth::handle_auth_request;
use crate::admin::handle_admin_command;
use std::net::TcpStream;
use std::io::{Read, Write};

pub fn handle_client(mut stream: TcpStream) {
    let peer_addr = stream.peer_addr().unwrap();
    println!("🔗 New client connected: {}", peer_addr);
    
    let mut buffer = [0; 4096];
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("❌ Client {} disconnected", peer_addr);
                break;
            }
            Ok(n) => {
                let received = String::from_utf8_lossy(&buffer[0..n]);
                let command = received.trim();
                println!("📨 Received from {}: {}", peer_addr, command);
                
                let response = if command.starts_with("auth:") {
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
                                Ok(_) => "✅ Folder scan completed successfully".to_string(),
                                Err(e) => format!("❌ Scan failed: {}", e),
                            }
                        }
                        "status" => {
                            match load_server_config("server_config.json") {
                                Ok(config) => {
                                    let (folders, files) = count_items(&config.folder_structure);
                                    format!("📊 Status: {} folders, {} files. {} MAC permissions. Last scan: {}", 
                                           folders, files, config.mac_permissions.len(), config.last_scan)
                                }
                                Err(_) => "❌ No configuration found. Run 'scan' first.".to_string(),
                            }
                        }
                        _ => format!("🤖 Unknown command: {}. Use 'auth:MAC' or 'admin:MAC:COMMAND'", command),
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
