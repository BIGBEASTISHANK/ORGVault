let currentStatus = 'disconnected';
let currentMac = '';
let folderData = null;

function updateStatus(connected, message = '') {
    const statusEl = document.getElementById('status');
    if (connected) {
        statusEl.textContent = '🟢 Connected';
        statusEl.className = 'status-indicator status-connected';
        currentStatus = 'connected';
    } else {
        statusEl.textContent = '🔴 ' + (message || 'Disconnected');
        statusEl.className = 'status-indicator status-error';
        currentStatus = 'disconnected';
    }
}

function updateMacDisplay(mac) {
    document.getElementById('mac-display').textContent = `MAC: ${mac}`;
    currentMac = mac;
}

async function loadFolders() {
    const container = document.getElementById('folder-structure');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading folder structure...</div>';
    
    try {
        const response = await fetch('/api/folders');
        const data = await response.json();
        
        if (data.error) {
            updateStatus(false, data.error);
            container.innerHTML = `<div class="error">❌ ${data.error}<br><small>MAC: ${data.mac_address || 'Unknown'}</small></div>`;
            if (data.mac_address) updateMacDisplay(data.mac_address);
            return;
        }
        
        updateStatus(true);
        if (data.mac_address) updateMacDisplay(data.mac_address);
        
        folderData = data.folder_structure;
        const tree = renderFolderTree(data.folder_structure);
        container.innerHTML = '';
        container.appendChild(tree);
        
    } catch (error) {
        updateStatus(false, 'Connection failed');
        container.innerHTML = `<div class="error">❌ Failed to load folder structure: ${error.message}</div>`;
    }
}

function renderFolderTree(node) {
    const ul = document.createElement('ul');
    const li = document.createElement('li');
    
    li.textContent = node.name;
    li.className = node.is_dir ? 'folder' : 'file';
    li.title = node.path;
    
    if (!node.is_dir) {
        li.onclick = () => showFileContent(node);
    }
    
    if (node.is_dir && node.children && node.children.length > 0) {
        const childUl = document.createElement('ul');
        node.children.forEach(child => {
            const childTree = renderFolderTree(child);
            childTree.querySelectorAll('li').forEach(childLi => {
                childUl.appendChild(childLi);
            });
        });
        li.appendChild(childUl);
    }
    
    ul.appendChild(li);
    return ul;
}

function showFileContent(fileNode) {
    const contentDiv = document.getElementById('file-content');
    
    if (fileNode.content) {
        contentDiv.innerHTML = `
            <div style="margin-bottom: 15px; padding: 10px; background: #e9ecef; border-radius: 6px;">
                <strong>📄 ${fileNode.name}</strong><br>
                <small>📁 ${fileNode.path}</small><br>
                <small>📏 Size: ${fileNode.size ? Math.round(fileNode.size / 1024) + ' KB' : 'Unknown'}</small>
            </div>
            <div style="background: white; padding: 15px; border-radius: 6px; max-height: 400px; overflow-y: auto; border: 1px solid #dee2e6;">
                ${escapeHtml(fileNode.content)}
            </div>
        `;
    } else {
        contentDiv.innerHTML = `
            <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-radius: 6px;">
                <strong>📄 ${fileNode.name}</strong><br>
                <small>📁 ${fileNode.path}</small><br>
                <small>⚠️ File content not available (binary file or no read permission)</small>
            </div>
        `;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function triggerScan() {
    try {
        const response = await fetch('/api/scan');
        const data = await response.json();
        alert(data.message || 'Scan completed');
        loadFolders();
    } catch (error) {
        alert('Failed to trigger scan: ' + error.message);
    }
}

async function getStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        alert(data.status || 'No status available');
    } catch (error) {
        alert('Failed to get status: ' + error.message);
    }
}

// Load folders on page load
window.onload = function() {
    loadFolders();
};

// Auto-refresh every 30 seconds
setInterval(() => {
    if (currentStatus === 'connected') {
        loadFolders();
    }
}, 30000);
