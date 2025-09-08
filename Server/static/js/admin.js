let availableFolders = [];

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
        
        availableFolders = data;
        
        document.getElementById('folder-list').innerHTML = data.map(folder => 
            `<div class="folder-checkbox">${folder}</div>`
        ).join('');
        
        populateFolderDropdown();
        
    } catch (error) {
        document.getElementById('folder-list').innerHTML = `<div style="color: red;">Error: ${error.message}</div>`;
    }
}

function populateFolderDropdown() {
    const checkboxContainer = document.getElementById('folder-checkboxes');
    checkboxContainer.innerHTML = '';
    
    availableFolders.forEach((folder, index) => {
        const div = document.createElement('div');
        div.className = 'dropdown-item';
        div.innerHTML = `
            <input type="checkbox" id="folder-${index}" value="${folder}" onchange="updateSelectedFolders()">
            <label for="folder-${index}">${folder}</label>
        `;
        checkboxContainer.appendChild(div);
    });
}

function toggleDropdown() {
    const dropdown = document.getElementById('folder-dropdown');
    const btn = document.querySelector('.dropdown-btn');
    
    dropdown.classList.toggle('show');
    btn.classList.toggle('active');
}

function toggleSelectAll() {
    const selectAllCheckbox = document.getElementById('select-all');
    const folderCheckboxes = document.querySelectorAll('#folder-checkboxes input[type="checkbox"]');
    
    folderCheckboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
    
    updateSelectedFolders();
}

function updateSelectedFolders() {
    const checkedBoxes = document.querySelectorAll('#folder-checkboxes input[type="checkbox"]:checked');
    const selectedFolders = Array.from(checkedBoxes).map(checkbox => checkbox.value);
    
    document.getElementById('selected-folders').value = JSON.stringify(selectedFolders);
    
    const displayText = selectedFolders.length === 0 
        ? 'Select folders...' 
        : selectedFolders.length === 1 
            ? selectedFolders[0]
            : `${selectedFolders.length} folders selected`;
    
    document.getElementById('selected-folders-text').textContent = displayText;
    
    const selectAllCheckbox = document.getElementById('select-all');
    const allCheckboxes = document.querySelectorAll('#folder-checkboxes input[type="checkbox"]');
    selectAllCheckbox.checked = checkedBoxes.length === allCheckboxes.length;
}

document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('folder-dropdown');
    const btn = document.querySelector('.dropdown-btn');
    
    if (!btn.contains(event.target) && !dropdown.contains(event.target)) {
        dropdown.classList.remove('show');
        btn.classList.remove('active');
    }
});

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

async function addMacPermission(event) {
    event.preventDefault();
    
    const mac = document.getElementById('new-mac').value.trim();
    const username = document.getElementById('new-username').value.trim();
    const selectedFoldersJson = document.getElementById('selected-folders').value;
    const canRead = document.getElementById('new-can-read').checked;
    const isAdmin = document.getElementById('new-is-admin').checked;
    
    let selectedFolders = [];
    try {
        selectedFolders = JSON.parse(selectedFoldersJson || '[]');
    } catch (e) {
        selectedFolders = [];
    }
    
    if (!mac || !username || selectedFolders.length === 0) {
        alert('Please fill in all required fields and select at least one folder');
        return;
    }
    
    // Validate MAC address format
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    if (!macRegex.test(mac)) {
        alert('Please enter a valid MAC address format (e.g., 00:00:00:00:00:00)');
        return;
    }
    
    // Create the request payload with exact field names
    const requestData = {
        mac_address: mac,
        username: username,
        allowed_folders: selectedFolders,
        can_read_files: canRead,  // Note: exact field name match
        is_admin: isAdmin
    };
    
    console.log('Sending request:', requestData); // Debug log
    
    try {
        const response = await fetch('/api/mac/add', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert(data.message || 'Operation completed successfully');
            
            // Clear form
            document.getElementById('mac-form').reset();
            document.getElementById('selected-folders').value = '';
            document.getElementById('selected-folders-text').textContent = 'Select folders...';
            
            // Uncheck all folder checkboxes
            document.querySelectorAll('#folder-checkboxes input[type="checkbox"]').forEach(checkbox => {
                checkbox.checked = false;
            });
            document.getElementById('select-all').checked = false;
            
            // Close dropdown
            document.getElementById('folder-dropdown').classList.remove('show');
            document.querySelector('.dropdown-btn').classList.remove('active');
            
            // Reload permissions
            loadMacPermissions();
        } else {
            alert('Error: ' + (data.message || 'Unknown error occurred'));
        }
        
    } catch (error) {
        alert('Network Error: ' + error.message);
        console.error('Request failed:', error);
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
