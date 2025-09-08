use std::path::Path;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub checksum: String,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SyncMetadata {
    pub files: Vec<FileRecord>,
    pub last_sync: Option<DateTime<Utc>>,
    pub server_url: String,
    pub client_id: String,
    pub encryption_key: Option<String>,
}

impl SyncMetadata {
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let metadata: SyncMetadata = serde_json::from_reader(reader)?;
            Ok(metadata)
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
        self.files.iter().find(|f| f.path == path)
    }

    pub fn update_file_record(&mut self, record: FileRecord) {
        if let Some(existing) = self.files.iter_mut().find(|f| f.path == record.path) {
            *existing = record;
        } else {
            self.files.push(record);
        }
    }

    pub fn remove_file_record(&mut self, path: &str) {
        self.files.retain(|f| f.path != path);
    }
}
