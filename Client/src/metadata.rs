use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::path::Path;
use std::fs::{File, remove_file};
use std::io::{BufReader, BufWriter};
use anyhow::Result;
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub checksum: String,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SyncMetadata {
    pub files: std::collections::HashMap<String, FileRecord>,
    pub last_sync: Option<DateTime<Utc>>,
    pub server_url: String,
    pub client_id: String,
    pub encryption_key: Option<String>,
}

impl SyncMetadata {
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            match File::open(&path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    match serde_json::from_reader::<_, SyncMetadata>(reader) {
                        Ok(metadata) => Ok(metadata),
                        Err(e) => {
                            eprintln!("⚠️ Corrupted metadata file: {}", e);
                            eprintln!("🗑️ Deleting corrupted metadata file...");
                            let _ = remove_file(&path);
                            Ok(SyncMetadata::default())
                        }
                    }
                }
                Err(_) => Ok(SyncMetadata::default()),
            }
        } else {
            Ok(SyncMetadata::default())
        }
    }

    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;
        Ok(())
    }

    pub fn get_file_record(&self, path: &str) -> Option<&FileRecord> {
        self.files.get(path)
    }

    pub fn update_file_record(&mut self, record: FileRecord) {
        self.files.insert(record.path.clone(), record);
    }

    pub fn remove_file_record(&mut self, path: &str) {
        self.files.remove(path);
    }
}

pub fn calculate_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
