use crate::config::{load_server_config, MacPermission};

pub fn is_admin_mac(mac_address: &str) -> bool {
    match load_server_config("server_config.json") {
        Ok(config) => {
            if let Some(permission) = config.mac_permissions.get(mac_address) {
                permission.is_admin
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

pub fn get_user_permissions(mac_address: &str) -> Result<MacPermission, String> {
    match load_server_config("server_config.json") {
        Ok(config) => {
            if let Some(permission) = config.mac_permissions.get(mac_address) {
                // If user is admin, give them access to ALL folders
                if permission.is_admin {
                    let mut admin_permission = permission.clone();
                    // Grant access to all available folders
                    admin_permission.allowed_folders = config.available_folders.clone();
                    println!("👑 Admin user granted access to {} folders", admin_permission.allowed_folders.len());
                    Ok(admin_permission)
                } else {
                    Ok(permission.clone())
                }
            } else {
                Err("MAC address not authorized".to_string())
            }
        }
        Err(e) => Err(format!("Config error: {}", e)),
    }
}

pub fn handle_auth_request(mac_address: &str) -> String {
    match get_user_permissions(mac_address) {
        Ok(permission) => {
            if permission.is_admin {
                println!("👑 Admin user authenticated: {} ({})", permission.username, mac_address);
                println!("📁 Admin granted access to {} folders", permission.allowed_folders.len());
            } else {
                println!("✅ Regular user authenticated: {} ({})", permission.username, mac_address);
            }
            
            // Build folder structure for accessible folders
            let mut folder_structure = serde_json::json!({
                "name": "Secure Vault",
                "path": "/",
                "is_dir": true,
                "children": []
            });

            // Add all accessible folders to the structure
            for folder_path in &permission.allowed_folders {
                let folder_name = folder_path.split('/').last().unwrap_or("Unknown");
                let folder_entry = serde_json::json!({
                    "name": folder_name,
                    "path": folder_path,
                    "is_dir": true,
                    "children": []
                });
                
                if let Some(children) = folder_structure["children"].as_array_mut() {
                    children.push(folder_entry);
                }
            }

            serde_json::to_string(&folder_structure).unwrap_or_else(|_| "{}".to_string())
        }
        Err(error) => format!("❌ Authentication failed: {}", error),
    }
}
