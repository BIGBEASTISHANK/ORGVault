mod config;
mod folder_scanner;
mod auth;
mod server;
mod admin;
mod web_admin; // New module for web admin

use std::net::TcpListener;
use std::thread;
use folder_scanner::scan_and_save_org_folders;
use server::handle_client;

fn main() -> std::io::Result<()> {
    println!("🚀 Secure Data Vault Server Starting...");
    
    let root_path = "/home/ishank/ORGCenterFolder";
    let config_path = "server_config.json";
    
    // Initial scan
    match scan_and_save_org_folders(root_path, config_path) {
        Ok(_) => println!("✅ Initial folder scan completed"),
        Err(e) => {
            eprintln!("⚠️  Initial scan failed: {}", e);
            println!("📝 Server will still start, but folder structure may be empty");
        }
    }
    
    // Start admin web interface in a separate thread
    thread::spawn(|| {
        if let Err(e) = web_admin::start_admin_server() {
            eprintln!("❌ Failed to start admin web interface: {}", e);
        }
    });
    
    // Start main TCP server
    let listener = TcpListener::bind("192.168.1.2:7878")?;
    println!("📡 Main server listening on 192.168.1.2:7878");
    println!("👑 Admin web interface available at http://192.168.1.2:8080");
    println!("🔐 MAC-based access control enabled");
    println!("📂 Ready for client connections");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("❌ Failed to accept connection: {}", e);
            }
        }
    }
    
    Ok(())
}
