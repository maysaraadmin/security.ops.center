// SIEM Dashboard - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Connect to WebSocket
    const socket = io();
    
    // DOM Elements
    const siemStatus = document.getElementById('siem-status');
    const statusCards = document.getElementById('status-cards');
    const componentsList = document.getElementById('components-list');
    const logContainer = document.getElementById('log-container');
    const clearLogsBtn = document.getElementById('clear-logs');
    const startAllBtn = document.getElementById('start-all-btn');
    const stopAllBtn = document.getElementById('stop-all-btn');
    const statsContainer = document.getElementById('stats-container');
    
    // Initialize the UI
    function initUI(status) {
        updateStatus(status);
        updateComponents(status.components);
        updateStats(status.stats);
    }
    
    // Update overall status
    function updateStatus(status) {
        siemStatus.textContent = status.status.charAt(0).toUpperCase() + status.status.slice(1);
        siemStatus.className = `badge bg-${status.status === 'running' ? 'success' : 'danger'}`;
    }
    
    // Update components list
    function updateComponents(components) {
        componentsList.innerHTML = '';
        
        for (const [name, component] of Object.entries(components)) {
            const enabled = component.enabled !== false; // default to true if not specified
            const statusClass = `status-${component.status || 'stopped'}`;
            const displayName = name.split('_').map(word => 
                word.charAt(0).toUpperCase() + word.slice(1)
            ).join(' ');
            
            const card = document.createElement('div');
            card.className = 'card component-card mb-2';
            card.innerHTML = `
                <div class="card-body p-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="card-title mb-1">${displayName}</h6>
                            <div class="d-flex align-items-center">
                                <span class="status-indicator ${statusClass}"></span>
                                <small class="text-muted">${component.status || 'stopped'}</small>
                            </div>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-success start-btn" 
                                    data-component="${name}" 
                                    ${!enabled || component.status === 'running' ? 'disabled' : ''}>
                                <i class="bi bi-play-fill"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger stop-btn" 
                                    data-component="${name}" 
                                    ${!enabled || component.status !== 'running' ? 'disabled' : ''}>
                                <i class="bi bi-stop-fill"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            componentsList.appendChild(card);
        }
        
        // Add event listeners to the new buttons
        document.querySelectorAll('.start-btn').forEach(btn => {
            btn.addEventListener('click', handleStartComponent);
        });
        
        document.querySelectorAll('.stop-btn').forEach(btn => {
            btn.addEventListener('click', handleStopComponent);
        });
    }
    
    // Update statistics
    function updateStats(stats) {
        statsContainer.innerHTML = `
            <div class="mb-3">
                <div class="d-flex justify-content-between">
                    <span>Events Processed:</span>
                    <strong>${stats.events_processed || 0}</strong>
                </div>
                <div class="progress mt-1" style="height: 5px;">
                    <div class="progress-bar" role="progressbar" 
                         style="width: ${Math.min(100, (stats.events_processed || 0) % 100)}%" 
                         aria-valuenow="${stats.events_processed || 0}" 
                         aria-valuemin="0" 
                         aria-valuemax="100">
                    </div>
                </div>
            </div>
            <div class="mb-3">
                <div class="d-flex justify-content-between">
                    <span>Alerts Triggered:</span>
                    <strong>${stats.alerts_triggered || 0}</strong>
                </div>
            </div>
            <div>
                <div class="d-flex justify-content-between">
                    <span>Uptime:</span>
                    <strong>${formatUptime(stats.uptime || 0)}</strong>
                </div>
            </div>
        `;
    }
    
    // Format uptime in a human-readable format
    function formatUptime(seconds) {
        if (!seconds) return '0s';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        const parts = [];
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
        
        return parts.join(' ');
    }
    
    // Add a log entry to the log container
    function addLogEntry(entry) {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${entry.level || 'info'}`;
        
        // Format timestamp
        const timestamp = new Date(entry.timestamp || Date.now());
        const timeStr = timestamp.toLocaleTimeString();
        
        // Truncate long messages
        let message = entry.message || '';
        if (message.length > 200) {
            message = message.substring(0, 200) + '...';
        }
        
        logEntry.innerHTML = `
            <span class="text-muted">[${timeStr}]</span>
            <span class="ms-2">${message}</span>
        `;
        
        logContainer.insertBefore(logEntry, logContainer.firstChild);
        
        // Limit the number of log entries to prevent performance issues
        while (logContainer.children.length > 1000) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }
    
    // Event Handlers
    function handleStartComponent(e) {
        const component = e.target.closest('button').dataset.component;
        if (!component) return;
        
        socket.emit('start_component', { component });
    }
    
    function handleStopComponent(e) {
        const component = e.target.closest('button').dataset.component;
        if (!component) return;
        
        socket.emit('stop_component', { component });
    }
    
    function handleStartAll() {
        // In a real implementation, we would emit an event to start all components
        alert('Starting all components...');
    }
    
    function handleStopAll() {
        // In a real implementation, we would emit an event to stop all components
        if (confirm('Are you sure you want to stop all components?')) {
            alert('Stopping all components...');
        }
    }
    
    // Event Listeners
    clearLogsBtn.addEventListener('click', () => {
        logContainer.innerHTML = '';
    });
    
    startAllBtn.addEventListener('click', handleStartAll);
    stopAllBtn.addEventListener('click', handleStopAll);
    
    // Socket.io event listeners
    socket.on('connect', () => {
        console.log('Connected to WebSocket server');
        addLogEntry({
            level: 'success',
            message: 'Connected to SIEM server'
        });
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from WebSocket server');
        addLogEntry({
            level: 'error',
            message: 'Disconnected from SIEM server. Attempting to reconnect...'
        });
    });
    
    socket.on('status_update', (status) => {
        initUI(status);
    });
    
    socket.on('log', (logEntry) => {
        addLogEntry(logEntry);
    });
    
    // Initial fetch of status
    fetch('/api/status')
        .then(response => response.json())
        .then(initUI)
        .catch(error => {
            console.error('Error fetching initial status:', error);
            addLogEntry({
                level: 'error',
                message: `Failed to fetch initial status: ${error.message}`
            });
        });
    
    // Simulate some log entries for demo purposes
    const demoLogs = [
        'SIEM system initialized',
        'Loading configuration from config/siem.yaml',
        'Starting log collector service',
        'Starting correlation engine',
        'Initializing database connection',
        'Starting API server on port 5000',
        'All components started successfully'
    ];
    
    demoLogs.forEach((message, index) => {
        setTimeout(() => {
            addLogEntry({
                level: 'info',
                message,
                timestamp: Date.now() - (demoLogs.length - index) * 1000
            });
        }, index * 500);
    });
});
