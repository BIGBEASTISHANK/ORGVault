async function loadServerInfo() {
    try {
        const response = await fetch('/api/server-info');
        const data = await response.json();
        
        document.getElementById('server-info').innerHTML = `
            <strong>Server MAC Address:</strong> <code>${data.server_mac}</code><br>
            <strong>Last Updated:</strong> ${new Date(data.timestamp).toLocaleString()}
        `;
        
    } catch (error) {
        document.getElementById('server-info').innerHTML = `<div style="color: red;">Error loading server info: ${error.message}</div>`;
    }
}

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
            `<div class="folder-checkbox" onclick="addFolderToInput('${folder}')">${folder}</div>`
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
    loadServerInfo();
    loadFolders();
    loadMacPermissions();
};
