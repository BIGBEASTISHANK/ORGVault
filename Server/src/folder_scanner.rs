use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};
use chrono::Utc;
use crate::config::{save_server_config, load_server_config};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FolderNode {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
    pub children: Vec<FolderNode>,
    pub content: Option<String>,
}

pub fn scan_and_save_org_folders(org_folder_path: &str, config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔═══════════════════════════════════════════╗");
    println!("║           📁 FOLDER SCANNER STARTED        ║");
    println!("╠═══════════════════════════════════════════╣");
    println!("║ Scanning: {:<31} ║", org_folder_path);
    println!("║ Config:   {:<31} ║", config_path);
    println!("╚═══════════════════════════════════════════╝\n");
    
    // Load existing config or create new
    let mut config = load_server_config(config_path).unwrap_or_default();
    
    // Clear existing folder data
    config.available_folders.clear();
    
    // Scan the ORGCenterFolder
    let org_path = Path::new(org_folder_path);
    
    if !org_path.exists() {
        println!("❌ ERROR: ORGCenterFolder does not exist: {}", org_folder_path);
        return Err(format!("ORGCenterFolder not found: {}", org_folder_path).into());
    }
    
    println!("📂 SCANNING SUBDIRECTORIES:");
    println!("─────────────────────────────────────────");
    
    // Get direct subdirectories (team folders)
    let mut team_folders = Vec::new();
    
    match fs::read_dir(org_path) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() {
                        let folder_name = entry.file_name().to_string_lossy().to_string();
                        
                        println!("📁 Found team folder: {}", folder_name);
                        
                        // Add to available folders (full path)
                        config.available_folders.push(path.to_string_lossy().to_string());
                        team_folders.push(folder_name);
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ ERROR reading directory: {}", e);
            return Err(format!("Cannot read ORGCenterFolder: {}", e).into());
        }
    }
    
    println!("─────────────────────────────────────────");
    println!("📊 SCAN RESULTS:");
    println!("   📁 Team folders found: {}", team_folders.len());
    for (i, folder) in team_folders.iter().enumerate() {
        println!("   {}. {}", i + 1, folder);
    }
    println!();
    
    // Build complete folder structure
    println!("🏗️ BUILDING FOLDER STRUCTURE:");
    if let Some(folder_tree) = build_folder_tree(org_path) {
        // Convert FolderNode to FolderEntry format expected by config
        config.folder_structure = convert_folder_node_to_entry(folder_tree);
        println!("✅ Folder structure built successfully");
    } else {
        println!("❌ Failed to build folder structure");
        return Err("Failed to build folder structure".into());
    }

    println!("👑 SETTING ADMIN PERMISSIONS:");
    println!("─────────────────────────────────────────");
    
    for (mac, permission) in config.mac_permissions.iter_mut() {
        if permission.is_admin {
            println!("   📁 Granting admin {} access to all {} folders", permission.username, config.available_folders.len());
            
            // Give admin access to all discovered folders
            permission.allowed_folders = config.available_folders.clone();
            
            for (i, folder) in config.available_folders.iter().enumerate() {
                println!("      {}. {}", i + 1, folder);
            }
        }
    }
    
    // Update timestamp as string
    config.last_scan = Utc::now().to_rfc3339();
    
    // Save updated config (fix argument order)
    match save_server_config(config_path, &config) {
        Ok(_) => {
            println!("✅ Config saved successfully");
            println!("\n╔═══════════════════════════════════════════╗");
            println!("║         📁 FOLDER SCAN COMPLETED          ║");
            println!("╠═══════════════════════════════════════════╣");
            println!("║ Total folders: {:<27} ║", config.available_folders.len());
            println!("║ Last scan:     {:<27} ║", config.last_scan);
            println!("╚═══════════════════════════════════════════╝\n");
            Ok(())
        }
        Err(e) => {
            println!("❌ ERROR saving config: {}", e);
            Err(format!("Failed to save config: {}", e).into())
        }
    }
}

fn build_folder_tree(path: &Path) -> Option<FolderNode> {
    let metadata = fs::metadata(path).ok()?;
    let is_dir = metadata.is_dir();
    let name = path.file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("root"))
        .to_string_lossy()
        .to_string();
    
    let mut children = Vec::new();
    
    if is_dir {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let child_path = entry.path();
                    if let Some(child_node) = build_folder_tree(&child_path) {
                        children.push(child_node);
                    }
                }
            }
        }
    }
    
    Some(FolderNode {
        name,
        path: path.to_string_lossy().to_string(),
        is_dir,
        size: if is_dir { None } else { Some(metadata.len()) },
        modified: metadata.modified().ok().map(|t| format!("{:?}", t)),
        children,
        content: None,
    })
}

fn convert_folder_node_to_entry(node: FolderNode) -> crate::config::FolderEntry {
    let children_vec: Vec<crate::config::FolderEntry> = node.children.into_iter()
        .map(convert_folder_node_to_entry)
        .collect();
    
    crate::config::FolderEntry {
        name: node.name,
        path: node.path,
        is_dir: node.is_dir,
        size: node.size,
        modified: node.modified,
        children: if children_vec.is_empty() { None } else { Some(children_vec) },
        content: node.content,
    }
}
