use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use anyhow::Result;
use log::{info, warn, error};

use crate::sync_client::SyncClient;

pub struct FileWatcher {
    _watcher: notify::RecommendedWatcher,
}

impl FileWatcher {
    pub fn new(
        watch_path: PathBuf,
        client: Arc<Mutex<SyncClient>>,
    ) -> Result<Self> {
        use notify::event::{CreateKind, ModifyKind, RemoveKind};
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();

        let mut watcher = notify::recommended_watcher(tx)?;
        watcher.watch(&watch_path, RecursiveMode::Recursive)?;

        info!("👁️ Started watching: {:?}", watch_path);

        // Spawn background task to handle file system events
        let client_clone = client.clone();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv() {
                if let Ok(event) = event {
                    match event.kind {
                        EventKind::Create(CreateKind::File) |
                        EventKind::Modify(ModifyKind::Data(_)) => {
                            for path in &event.paths {
                                if let Some(relative_path) = path.strip_prefix(&watch_path).ok() {
                                    info!("📝 File changed: {:?}", relative_path);
                                    
                                    let mut client_lock = client_clone.lock().await;
                                    if let Err(e) = client_lock.upload_file(relative_path).await {
                                        error!("Failed to upload file {:?}: {}", relative_path, e);
                                    }
                                }
                            }
                        }
                        EventKind::Remove(RemoveKind::File) => {
                            for path in &event.paths {
                                if let Some(relative_path) = path.strip_prefix(&watch_path).ok() {
                                    info!("🗑️ File deleted: {:?}", relative_path);
                                    
                                    let mut client_lock = client_clone.lock().await;
                                    if let Err(e) = client_lock.delete_file(relative_path).await {
                                        error!("Failed to delete file {:?}: {}", relative_path, e);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(Self {
            _watcher: watcher,
        })
    }
}
