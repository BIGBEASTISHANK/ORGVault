use crate::config::{FolderEntry, save_server_config, count_items};
use std::fs;
use std::path::Path;

pub fn scan_org_folders<P: AsRef<Path>>(path: P) -> Result<FolderEntry, std::io::Error> {
    let path = path.as_ref();
    let name = path.file_name()
        .unwrap_or_else(|| path.as_os_str())
        .to_string_lossy()
        .into_owned();
    
    let metadata = fs::metadata(path)?;
    let is_dir = metadata.is_dir();
    
    let size = if !is_dir { Some(metadata.len()) } else { None };
    let modified = metadata.modified()
        .ok()
        .map(|time| format!("{:?}", time));

    let content = if !is_dir && metadata.len() < 1_048_576 {
        match fs::read_to_string(path) {
            Ok(file_content) => Some(file_content),
            Err(_) => None,
        }
    } else {
        None
    };

    let children = if is_dir {
        let mut entries = Vec::new();
        
        match fs::read_dir(path) {
            Ok(dir_entries) => {
                for entry in dir_entries {
                    match entry {
                        Ok(entry) => {
                            let child_path = entry.path();
                            match scan_org_folders(child_path) {
                                Ok(child_entry) => entries.push(child_entry),
                                Err(e) => eprintln!("Error scanning {}: {}", entry.path().display(), e),
                            }
                        }
                        Err(e) => eprintln!("Error reading directory entry: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("Error reading directory {}: {}", path.display(), e),
        }
        
        Some(entries)
    } else {
        None
    };

    Ok(FolderEntry {
        name,
        path: path.to_string_lossy().into_owned(),
        is_dir,
        size,
        modified,
        children,
        content,
    })
}

pub fn scan_and_save_org_folders(root_path: &str, config_path: &str) -> Result<(), std::io::Error> {
    println!("🔍 Scanning ORG folders at: {}", root_path);
    
    if !Path::new(root_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Path does not exist: {}", root_path)
        ));
    }
    
    let folder_structure = scan_org_folders(root_path)?;
    let (folders, files) = count_items(&folder_structure);
    println!("📁 Found {} folders and {} files", folders, files);
    
    save_server_config(root_path, folder_structure, config_path)?;
    println!("💾 Configuration saved to: {}", config_path);
    
    Ok(())
}
