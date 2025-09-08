use crate::config::{FolderEntry, load_server_config};

pub fn filter_folder_by_permissions(
    folder: &FolderEntry, 
    allowed_paths: &[String], 
    can_read_files: bool
) -> Option<FolderEntry> {
    let is_allowed = allowed_paths.iter().any(|allowed_path| {
        folder.path.starts_with(allowed_path) || allowed_path.starts_with(&folder.path)
    });
    
    if !is_allowed {
        return None;
    }
    
    let mut filtered_folder = folder.clone();
    
    if !can_read_files {
        filtered_folder.content = None;
    }
    
    if let Some(ref children) = folder.children {
        let filtered_children: Vec<FolderEntry> = children
            .iter()
            .filter_map(|child| filter_folder_by_permissions(child, allowed_paths, can_read_files))
            .collect();
        
        filtered_folder.children = if filtered_children.is_empty() {
            None
        } else {
            Some(filtered_children)
        };
    }
    
    Some(filtered_folder)
}

pub fn handle_auth_request(mac_address: &str) -> String {
    match load_server_config("server_config.json") {
        Ok(config) => {
            if let Some(permission) = config.mac_permissions.get(mac_address) {
                println!("✅ MAC {} authenticated as {}", mac_address, permission.username);
                
                if let Some(filtered_structure) = filter_folder_by_permissions(
                    &config.folder_structure, 
                    &permission.allowed_folders, 
                    permission.can_read_files
                ) {
                    match serde_json::to_string(&filtered_structure) {
                        Ok(json) => json,
                        Err(e) => format!("❌ Failed to serialize folder structure: {}", e),
                    }
                } else {
                    "❌ No accessible folders for this MAC address".to_string()
                }
            } else {
                println!("❌ Unauthorized MAC address: {}", mac_address);
                "❌ Unauthorized: MAC address not found in permissions".to_string()
            }
        }
        Err(e) => format!("❌ Failed to load server config: {}", e),
    }
}

pub fn is_admin_mac(mac_address: &str) -> bool {
    match load_server_config("server_config.json") {
        Ok(config) => {
            config.mac_permissions
                .get(mac_address)
                .map(|perm| perm.is_admin)
                .unwrap_or(false)
        }
        Err(_) => false,
    }
}
