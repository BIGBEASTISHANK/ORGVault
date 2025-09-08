use crate::config::{load_server_config, MacPermission, ServerConfig, save_server_config};

pub fn handle_admin_command(mac_address: &str, command: &str) -> String {
    if !crate::auth::is_admin_mac(mac_address) {
        return "❌ Access denied: Admin privileges required".to_string();
    }

    let parts: Vec<&str> = command.split("|||").collect();
    
    match parts[0] {
        "admin_list_folders" => list_all_folders(),
        "admin_list_macs" => list_all_mac_permissions(),
        "admin_add_mac" => {
            if parts.len() >= 6 {
                add_mac_permission(parts[1], parts[2], parts[3], parts[4] == "true", parts[5] == "true")
            } else {
                "❌ Usage: admin_add_mac|||MAC|||USERNAME|||FOLDERS|||CAN_READ|||IS_ADMIN".to_string()
            }
        }
        "admin_remove_mac" => {
            if parts.len() >= 2 {
                remove_mac_permission(parts[1])
            } else {
                "❌ Usage: admin_remove_mac|||MAC_ADDRESS".to_string()
            }
        }
        _ => "❌ Unknown admin command".to_string(),
    }
}

fn list_all_folders() -> String {
    match load_server_config("server_config.json") {
        Ok(config) => {
            serde_json::to_string(&config.available_folders).unwrap_or_else(|_| "❌ Failed to serialize folders".to_string())
        }
        Err(e) => format!("❌ Failed to load config: {}", e),
    }
}

fn list_all_mac_permissions() -> String {
    match load_server_config("server_config.json") {
        Ok(config) => {
            serde_json::to_string(&config.mac_permissions).unwrap_or_else(|_| "❌ Failed to serialize MAC permissions".to_string())
        }
        Err(e) => format!("❌ Failed to load config: {}", e),
    }
}

fn add_mac_permission(mac: &str, username: &str, folders_str: &str, can_read: bool, is_admin: bool) -> String {
    match load_server_config("server_config.json") {
        Ok(mut config) => {
            let folders: Vec<String> = if folders_str.is_empty() {
                vec![]
            } else {
                folders_str.split(',').map(|s| s.trim().to_string()).collect()
            };
            
            let permission = MacPermission {
                mac_address: mac.to_string(),
                username: username.to_string(),
                allowed_folders: folders,
                can_read_files: can_read,
                is_admin,
            };
            
            config.mac_permissions.insert(mac.to_string(), permission);
            
            match save_server_config("server_config.json", &config) {
                Ok(_) => {
                    if is_admin {
                        format!("✅ Admin user {} ({}) added successfully with access to ALL folders", username, mac)
                    } else {
                        format!("✅ User {} ({}) added successfully", username, mac)
                    }
                }
                Err(e) => format!("❌ Failed to save config: {}", e),
            }
        }
        Err(e) => format!("❌ Failed to load config: {}", e),
    }
}

fn remove_mac_permission(mac: &str) -> String {
    match load_server_config("server_config.json") {
        Ok(mut config) => {
            if let Some(removed_user) = config.mac_permissions.remove(mac) {
                match save_server_config("server_config.json", &config) {
                    Ok(_) => format!("✅ User {} ({}) removed successfully", removed_user.username, mac),
                    Err(e) => format!("❌ Failed to save config: {}", e),
                }
            } else {
                format!("❌ MAC {} not found", mac)
            }
        }
        Err(e) => format!("❌ Failed to load config: {}", e),
    }
}
