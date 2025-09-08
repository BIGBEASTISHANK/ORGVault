use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FolderEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
    pub children: Option<Vec<FolderEntry>>,
    pub content: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MacPermission {
    pub mac_address: String,
    pub username: String,
    pub allowed_folders: Vec<String>,
    pub can_read_files: bool,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerConfig {
    pub root_path: String,
    pub last_scan: String,
    pub folder_structure: FolderEntry,
    pub mac_permissions: HashMap<String, MacPermission>,
    pub available_folders: Vec<String>,
}

pub fn create_default_mac_permissions() -> HashMap<String, MacPermission> {
    let mut permissions = HashMap::new();
    
    // Use your actual server MAC address (eno1 ethernet interface)
    permissions.insert("24:6a:0e:11:82:96".to_string(), MacPermission {
        mac_address: "24:6a:0e:11:82:96".to_string(),
        username: "ServerAdmin".to_string(),
        allowed_folders: vec!["/home/ishank/ORGCenterFolder".to_string()],
        can_read_files: true,
        is_admin: true,
    });
    
    permissions
}


pub fn save_server_config(
    root_path: &str, 
    folder_structure: FolderEntry, 
    config_path: &str
) -> std::io::Result<()> {
    let (mac_permissions, _available_folders) = match load_server_config(config_path) {
        Ok(existing_config) => (existing_config.mac_permissions, existing_config.available_folders),
        Err(_) => (create_default_mac_permissions(), Vec::new()),
    };
    
    let new_available_folders = extract_all_folder_paths(&folder_structure);
    
    let config = ServerConfig {
        root_path: root_path.to_string(),
        last_scan: chrono::Utc::now().to_rfc3339(),
        folder_structure,
        mac_permissions,
        available_folders: new_available_folders,
    };
    
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    fs::write(config_path, json)?;
    Ok(())
}

pub fn load_server_config(config_path: &str) -> Result<ServerConfig, std::io::Error> {
    let contents = fs::read_to_string(config_path)?;
    let config: ServerConfig = serde_json::from_str(&contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(config)
}

fn extract_all_folder_paths(folder: &FolderEntry) -> Vec<String> {
    let mut paths = Vec::new();
    
    if folder.is_dir {
        paths.push(folder.path.clone());
        
        if let Some(ref children) = folder.children {
            for child in children {
                paths.extend(extract_all_folder_paths(child));
            }
        }
    }
    
    paths
}

pub fn count_items(entry: &FolderEntry) -> (usize, usize) {
    if entry.is_dir {
        let mut folders = 1;
        let mut files = 0;
        
        if let Some(ref children) = entry.children {
            for child in children {
                let (child_folders, child_files) = count_items(child);
                folders += child_folders;
                files += child_files;
            }
        }
        
        (folders, files)
    } else {
        (0, 1)
    }
}
