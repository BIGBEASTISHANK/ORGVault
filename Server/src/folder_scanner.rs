use crate::config::{FolderEntry, ServerConfig, save_server_config, load_server_config};
use walkdir::WalkDir;
use std::fs;
use chrono::Utc;

pub fn scan_and_save_org_folders(org_folder_path: &str, config_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Scanning folder: {}", org_folder_path);
    
    let root_entry = scan_folder_recursive(org_folder_path)?;
    let available_folders = collect_folder_paths(org_folder_path);
    
    let mut config = match load_server_config(config_file) {
        Ok(existing_config) => existing_config,
        Err(_) => ServerConfig::default(),
    };
    
    config.folder_structure = root_entry;
    config.available_folders = available_folders;
    config.last_scan = Utc::now().to_rfc3339();
    
    save_server_config(config_file, &config)?;
    
    println!("✅ Folder scan completed and saved to {}", config_file);
    Ok(())
}

fn scan_folder_recursive(folder_path: &str) -> Result<FolderEntry, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(folder_path)?;
    let folder_name = std::path::Path::new(folder_path)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("root"))
        .to_string_lossy()
        .to_string();
    
    let mut entry = FolderEntry {
        name: folder_name,
        path: folder_path.to_string(),
        is_dir: metadata.is_dir(),
        size: if metadata.is_file() { Some(metadata.len()) } else { None },
        modified: Some(format!("{:?}", metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))),
        children: None,
        content: None,
    };
    
    if metadata.is_dir() {
        let mut children = Vec::new();
        
        match fs::read_dir(folder_path) {
            Ok(dir_entries) => {
                for dir_entry in dir_entries {
                    if let Ok(dir_entry) = dir_entry {
                        let child_path = dir_entry.path().to_string_lossy().to_string();
                        if let Ok(child_entry) = scan_folder_recursive(&child_path) {
                            children.push(child_entry);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not read directory {}: {}", folder_path, e);
            }
        }
        
        entry.children = Some(children);
    }
    
    Ok(entry)
}

fn collect_folder_paths(root_path: &str) -> Vec<String> {
    let mut folders = Vec::new();
    
    for entry in WalkDir::new(root_path).min_depth(1).max_depth(3) {
        if let Ok(entry) = entry {
            if entry.file_type().is_dir() {
                folders.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    
    folders
}
