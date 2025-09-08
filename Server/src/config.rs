use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MacPermission {
    pub mac_address: String,
    pub username: String,
    pub allowed_folders: Vec<String>,
    pub can_read_files: bool,
    pub is_admin: bool,
}

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

// Add this function for the serde default
fn default_encryption_key() -> String {
    "askjkldjfslkasjdfkl".to_string()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerConfig {
    pub mac_permissions: HashMap<String, MacPermission>,
    pub available_folders: Vec<String>,
    pub folder_structure: FolderEntry,
    pub last_scan: String,
    #[serde(default = "default_encryption_key")]
    pub encryption_key: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            mac_permissions: HashMap::new(),
            available_folders: vec![],
            folder_structure: FolderEntry {
                name: "Secure Vault".to_string(),
                path: "/".to_string(),
                is_dir: true,
                size: None,
                modified: None,
                children: Some(vec![]),
                content: None,
            },
            last_scan: Utc::now().to_rfc3339(),
            encryption_key: "askjkldjfslkasjdfkl".to_string(),
        }
    }
}

pub fn load_server_config(file_path: &str) -> Result<ServerConfig, std::io::Error> {
    match fs::read_to_string(file_path) {
        Ok(contents) => {
            serde_json::from_str(&contents).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                let default_config = ServerConfig::default();
                save_server_config(file_path, &default_config)?;
                Ok(default_config)
            } else {
                Err(e)
            }
        }
    }
}

pub fn save_server_config(file_path: &str, config: &ServerConfig) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(config)?;
    fs::write(file_path, json)
}

pub fn count_items(folder: &FolderEntry) -> (usize, usize) {
    let mut folders = 0;
    let mut files = 0;
    
    if folder.is_dir {
        folders += 1;
        if let Some(children) = &folder.children {
            for child in children {
                let (child_folders, child_files) = count_items(child);
                folders += child_folders;
                files += child_files;
            }
        }
    } else {
        files += 1;
    }
    
    (folders, files)
}
