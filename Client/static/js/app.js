let currentStatus = 'disconnected';
let currentMac = '';
let folderData = null;
let currentFolder = '';
let encryptionKey = '';

// Encryption/Decryption functions using Web Crypto API
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptFile(file, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    
    const fileData = await file.arrayBuffer();
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        fileData
    );
    
    // Combine salt + iv + encrypted data
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return combined;
}

async function decryptFile(encryptedData, password) {
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 28);
    const encrypted = encryptedData.slice(28);
    
    const key = await deriveKey(password, salt);
    
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        return new Uint8Array(decrypted);
    } catch (error) {
        throw new Error('Decryption failed - invalid key or corrupted data');
    }
}

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

async function showMacInfo() {
    try {
        const response = await fetch('/api/mac');
        const data = await response.json();
        
        if (data.error) {
            alert(`MAC Detection Error: ${data.error}`);
        } else {
            alert(`Your MAC Address: ${data.mac_address}\nDetected at: ${new Date(data.timestamp).toLocaleString()}`);
        }
    } catch (error) {
        alert('Failed to get MAC info: ' + error.message);
    }
}

function showEncryptionKey() {
    document.getElementById('key-modal').style.display = 'block';
    document.getElementById('encryption-key').value = '';
}

function closeKeyModal() {
    document.getElementById('key-modal').style.display = 'none';
}

function setEncryptionKey() {
    const key = document.getElementById('encryption-key').value;
    if (key.length < 8) {
        alert('Encryption key must be at least 8 characters long');
        return;
    }
    
    encryptionKey = key;
    localStorage.setItem('encryptionKey', key);
    closeKeyModal();
    alert('Encryption key set successfully!');
}

async function loadFolders() {
    const container = document.getElementById('folder-structure');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading folder structure...</div>';
    
    try {
        const response = await fetch('/api/folders');
        const data = await response.json();
        
        if (data.error) {
            updateStatus(false, data.error);
            container.innerHTML = `
                <div class="error">
                    ❌ ${data.error}<br>
                    <small>MAC: ${data.mac_address || 'Unknown'}</small>
                    ${data.message ? `<br><small>${data.message}</small>` : ''}
                </div>`;
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
    
    if (node.is_dir) {
        li.onclick = () => loadFiles(node.path, node.name);
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

async function loadFiles(folderPath, folderName) {
    currentFolder = folderPath;
    document.getElementById('current-folder').textContent = `📁 ${folderName}`;
    
    const fileList = document.getElementById('file-list');
    fileList.innerHTML = '<div class="loading">Loading files...</div>';
    
    try {
        const response = await fetch(`http://192.168.1.2:8080/api/files?folder=${encodeURIComponent(folderPath)}&mac=${encodeURIComponent(currentMac)}`);
        const files = await response.json();
        
        if (files.error) {
            fileList.innerHTML = `<div class="error">❌ ${files.error}</div>`;
            return;
        }
        
        if (files.length === 0) {
            fileList.innerHTML = '<div class="no-files">📂 This folder is empty</div>';
            return;
        }
        
        let html = '';
        files.forEach(file => {
            if (file.is_file) {
                html += `
                    <div class="file-item">
                        <div class="file-info">
                            <div class="file-icon">📄</div>
                            <div class="file-details">
                                <div class="file-name">${file.name}</div>
                                <div class="file-meta">${formatFileSize(file.size)} • ${formatDate(file.modified)}</div>
                            </div>
                        </div>
                        <div class="file-actions-buttons">
                            <button class="btn btn-primary btn-small" onclick="downloadFile('${file.name}')">📥 Download</button>
                        </div>
                    </div>
                `;
            }
        });
        
        fileList.innerHTML = html || '<div class="no-files">📂 No files in this folder</div>';
        
    } catch (error) {
        fileList.innerHTML = `<div class="error">❌ Failed to load files: ${error.message}</div>`;
    }
}

async function downloadFile(filename) {
    if (!encryptionKey) {
        encryptionKey = localStorage.getItem('encryptionKey');
        if (!encryptionKey) {
            alert('Please set an encryption key first');
            showEncryptionKey();
            return;
        }
    }
    
    try {
        const response = await fetch(`http://192.168.1.2:8080/api/download/${encodeURIComponent(filename)}?folder=${encodeURIComponent(currentFolder)}&mac=${encodeURIComponent(currentMac)}`);
        
        if (!response.ok) {
            const error = await response.json();
            alert(`Download failed: ${error.error}`);
            return;
        }
        
        const encryptedData = new Uint8Array(await response.arrayBuffer());
        
        // Decrypt the file
        const decryptedData = await decryptFile(encryptedData, encryptionKey);
        
        // Create download link
        const blob = new Blob([decryptedData]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        
        alert(`File "${filename}" downloaded and decrypted successfully!`);
        
    } catch (error) {
        alert(`Download/Decryption failed: ${error.message}`);
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('file-upload');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    if (!encryptionKey) {
        encryptionKey = localStorage.getItem('encryptionKey');
        if (!encryptionKey) {
            alert('Please set an encryption key first');
            showEncryptionKey();
            return;
        }
    }
    
    if (!currentFolder) {
        alert('Please select a folder first');
        return;
    }
    
    try {
        // Encrypt the file
        const encryptedData = await encryptFile(file, encryptionKey);
        
        // Create form data
        const formData = new FormData();
        const encryptedBlob = new Blob([encryptedData]);
        formData.append('file', encryptedBlob, file.name);
        
        const response = await fetch(`http://192.168.1.2:8080/api/upload?folder=${encodeURIComponent(currentFolder)}&mac=${encodeURIComponent(currentMac)}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            alert(`File "${file.name}" encrypted and uploaded successfully!`);
            // Reload file list
            loadFiles(currentFolder, currentFolder.split('/').pop());
        } else {
            alert(`Upload failed: ${result.error}`);
        }
        
        // Clear file input
        fileInput.value = '';
        
    } catch (error) {
        alert(`Upload/Encryption failed: ${error.message}`);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    try {
        return new Date(dateString).toLocaleDateString();
    } catch {
        return 'Unknown';
    }
}

// Load folders on page load
window.onload = function() {
    loadFolders();
    
    // Load saved encryption key
    const savedKey = localStorage.getItem('encryptionKey');
    if (savedKey) {
        encryptionKey = savedKey;
    }
};

// Auto-refresh every 30 seconds if connected
setInterval(() => {
    if (currentStatus === 'connected' && currentFolder) {
        loadFiles(currentFolder, currentFolder.split('/').pop());
    }
}, 30000);
