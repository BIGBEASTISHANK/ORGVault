use actix_web::{get, post, web, App, HttpServer, HttpResponse, Result};
use serde::Deserialize; // Removed unused Serialize
use crate::config::load_server_config; // Removed unused MacPermission
use crate::admin::handle_admin_command;
use crate::folder_scanner::scan_and_save_org_folders;

#[derive(Deserialize)]
struct MacRequest {
    mac_address: String,
    username: String,
    allowed_folders: Vec<String>,
    can_read_files: bool,
    is_admin: bool,
}

#[derive(Deserialize)]
struct RemoveMacRequest {
    mac_address: String,
}

#[get("/api/folders")]
async fn get_available_folders() -> Result<HttpResponse> {
    match load_server_config("server_config.json") {
        Ok(config) => Ok(HttpResponse::Ok().json(&config.available_folders)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to load config: {}", e)
        })))
    }
}

#[get("/api/macs")]
async fn get_mac_permissions() -> Result<HttpResponse> {
    match load_server_config("server_config.json") {
        Ok(config) => Ok(HttpResponse::Ok().json(&config.mac_permissions)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to load config: {}", e)
        })))
    }
}

#[post("/api/mac/add")]
async fn add_mac_permission(mac_req: web::Json<MacRequest>) -> Result<HttpResponse> {
    let folders_str = mac_req.allowed_folders.join(",");
    let command = format!(
        "admin_add_mac:{}:{}:{}:{}:{}",
        mac_req.mac_address,
        mac_req.username,
        folders_str,
        mac_req.can_read_files,
        mac_req.is_admin
    );
    
    let result = handle_admin_command("00:11:22:33:44:55", &command);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/mac/remove")]
async fn remove_mac_permission(mac_req: web::Json<RemoveMacRequest>) -> Result<HttpResponse> {
    let command = format!("admin_remove_mac:{}", mac_req.mac_address);
    let result = handle_admin_command("00:11:22:33:44:55", &command);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": result
    })))
}

#[post("/api/scan")]
async fn trigger_scan() -> Result<HttpResponse> {
    match scan_and_save_org_folders("/home/ishank/ORGCenterFolder", "server_config.json") {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "✅ Folder scan completed successfully"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Scan failed: {}", e)
        })))
    }
}

#[get("/")]
async fn admin_panel() -> Result<HttpResponse> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>👑 Secure Vault Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { text-align: center; margin-bottom: 30px; background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #f8f9fa; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
        .form-group { margin: 15px 0; }
        .form-group label { display: block; font-weight: bold; margin-bottom: 5px; }
        .folder-list { max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background: white; border-radius: 6px; }
        .mac-list { max-height: 400px; overflow-y: auto; }
        .mac-item { background: white; margin: 10px 0; padding: 15px; border-radius: 5px; border: 1px solid #dee2e6; position: relative; }
        .folder-checkbox { padding: 5px; border-bottom: 1px solid #eee; cursor: pointer; }
        .folder-checkbox:hover { background: #f0f0f0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👑 Secure Vault Admin Panel</h1>
            <p>Manage MAC Address Permissions and Folder Access</p>
        </div>

        <div class="section">
            <h3>🔍 Server Management</h3>
            <button class="btn btn-primary" onclick="triggerScan()">📂 Scan Folders</button>
            <button class="btn btn-primary" onclick="loadFolders()">🔄 Load Available Folders</button>
            <button class="btn btn-primary" onclick="loadMacPermissions()">👥 Load MAC Permissions</button>
        </div>

        <div class="section">
            <h3>📁 Available Folders</h3>
            <div id="folder-list" class="folder-list">Click "Load Available Folders" to see all folders</div>
        </div>

        <div class="section">
            <h3>➕ Add New MAC Permission</h3>
            <div class="form-group">
                <label>MAC Address:</label>
                <input type="text" id="new-mac" placeholder="00:11:22:33:44:55">
            </div>
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="new-username" placeholder="User Name">
            </div>
            <div class="form-group">
                <label>Allowed Folders (select from available folders above):</label>
                <textarea id="new-folders" rows="3" placeholder="Paste folder paths here, separated by commas"></textarea>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" id="new-can-read"> Can Read Files
                </label>
                <label style="margin-left: 20px;">
                    <input type="checkbox" id="new-is-admin"> Is Admin
                </label>
            </div>
            <button class="btn btn-success" onclick="addMacPermission()">➕ Add MAC Permission</button>
        </div>

        <div class="section">
            <h3>👥 Current MAC Permissions</h3>
            <div id="mac-list" class="mac-list">Click "Load MAC Permissions" to see current permissions</div>
        </div>
    </div>

    <script>
        async function triggerScan() {
            try {
                const response = await fetch('/api/scan', { method: 'POST' });
                const data = await response.json();
                alert(data.message || 'Scan completed');
                loadFolders();
            } catch (error) {
                alert('Failed to trigger scan: ' + error.message);
            }
        }

        async function loadFolders() {
            try {
                const response = await fetch('/api/folders');
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('folder-list').innerHTML = `<div style="color: red;">${data.error}</div>`;
                    return;
                }
                
                document.getElementById('folder-list').innerHTML = data.map(folder => 
                    `<div class="folder-checkbox" onclick="addFolderToInput('${folder}')">📁 ${folder}</div>`
                ).join('');
                
            } catch (error) {
                document.getElementById('folder-list').innerHTML = `<div style="color: red;">Error: ${error.message}</div>`;
            }
        }

        function addFolderToInput(folder) {
            const foldersTextarea = document.getElementById('new-folders');
            const currentValue = foldersTextarea.value.trim();
            
            if (currentValue) {
                foldersTextarea.value = currentValue + ',' + folder;
            } else {
                foldersTextarea.value = folder;
            }
        }

        async function loadMacPermissions() {
            try {
                const response = await fetch('/api/macs');
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('mac-list').innerHTML = `<div style="color: red;">${data.error}</div>`;
                    return;
                }
                
                let html = '';
                for (const [mac, perm] of Object.entries(data)) {
                    html += `
                        <div class="mac-item">
                            <strong>🔗 ${mac}</strong> - ${perm.username}
                            ${perm.is_admin ? '<span style="color: gold;">👑 Admin</span>' : ''}
                            <br>
                            <small>📁 Folders: ${perm.allowed_folders.join(', ')}</small>
                            <br>
                            <small>📖 Can Read: ${perm.can_read_files ? '✅' : '❌'}</small>
                            <button class="btn btn-danger" style="position: absolute; top: 10px; right: 10px;" onclick="removeMac('${mac}')">🗑️ Remove</button>
                        </div>
                    `;
                }
                
                document.getElementById('mac-list').innerHTML = html || '<div>No MAC permissions found</div>';
                
            } catch (error) {
                document.getElementById('mac-list').innerHTML = `<div style="color: red;">Error: ${error.message}</div>`;
            }
        }

        async function addMacPermission() {
            const mac = document.getElementById('new-mac').value.trim();
            const username = document.getElementById('new-username').value.trim();
            const folders = document.getElementById('new-folders').value.trim().split(',').map(f => f.trim()).filter(f => f);
            const canRead = document.getElementById('new-can-read').checked;
            const isAdmin = document.getElementById('new-is-admin').checked;
            
            if (!mac || !username || folders.length === 0) {
                alert('Please fill in all required fields');
                return;
            }
            
            try {
                const response = await fetch('/api/mac/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        mac_address: mac,
                        username: username,
                        allowed_folders: folders,
                        can_read_files: canRead,
                        is_admin: isAdmin
                    })
                });
                
                const data = await response.json();
                alert(data.message || 'Operation completed');
                
                // Clear form
                document.getElementById('new-mac').value = '';
                document.getElementById('new-username').value = '';
                document.getElementById('new-folders').value = '';
                document.getElementById('new-can-read').checked = false;
                document.getElementById('new-is-admin').checked = false;
                
                loadMacPermissions();
                
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function removeMac(mac) {
            if (!confirm(`Remove MAC ${mac}?`)) return;
            
            try {
                const response = await fetch('/api/mac/remove', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mac_address: mac })
                });
                
                const data = await response.json();
                alert(data.message || 'Operation completed');
                loadMacPermissions();
                
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        window.onload = function() {
            loadFolders();
            loadMacPermissions();
        };
    </script>
</body>
</html>
"#;

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

// FIXED: Use tokio::runtime::Builder instead of Runtime::new()
pub fn start_admin_server() -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    rt.block_on(async {
        println!("👑 Starting Admin Web Interface on 192.168.1.2:8080");
        
        HttpServer::new(|| {
            App::new()
                .service(admin_panel)
                .service(get_available_folders)
                .service(get_mac_permissions)
                .service(add_mac_permission)
                .service(remove_mac_permission)
                .service(trigger_scan)
        })
        .bind("192.168.1.2:8080")?
        .run()
        .await
    })
}
