"""
Unified SIEM Dashboard

A comprehensive dashboard that combines all SIEM monitoring and management features.
"""
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request, send_from_directory
from flask_cors import CORS
import psutil
import platform
import win32evtlog
import win32con

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_dashboard.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)

# In-memory storage for dashboard data
class DashboardData:
    def __init__(self):
        self.events = []
        self.metrics = {
            'system': {},
            'events': {
                'total': 0,
                'by_type': {},
                'by_severity': {}
            },
            'performance': {
                'cpu': 0,
                'memory': 0,
                'disk': 0,
                'network': 0
            }
        }
        self.last_updated = datetime.now()

dashboard_data = DashboardData()

# Utility Functions
def get_system_info():
    """Collect system information."""
    return {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'cpu_percent': psutil.cpu_percent(),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
    }

def get_sysmon_events(limit=100):
    """Fetch Sysmon events from Windows Event Log."""
    events = []
    event_types = {}
    
    try:
        hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        count = 0
        while count < limit:
            results = win32evtlog.ReadEventLog(hand, flags, 0)
            if not results:
                break
                
            for event in results:
                if count >= limit:
                    break
                    
                event_type = f'Event {event.EventID}'
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                event_data = {
                    'id': count + 1,
                    'timestamp': event.TimeGenerated.Format(),
                    'event_id': event.EventID,
                    'source': event.SourceName,
                    'computer': event.ComputerName,
                    'level': 'info',
                    'data': []
                }
                
                # Set event level based on ID
                if event.EventID in [1, 8, 10]:  # Critical events
                    event_data['level'] = 'high'
                elif event.EventID in [3, 11, 12, 13, 14]:  # Important events
                    event_data['level'] = 'medium'
                else:  # Informational events
                    event_data['level'] = 'low'
                
                if event.StringInserts:
                    event_data['data'] = [str(item) for item in event.StringInserts]
                
                events.append(event_data)
                count += 1
                
    except Exception as e:
        logger.error(f"Error reading Sysmon events: {e}")
    finally:
        if 'hand' in locals():
            win32evtlog.CloseEventLog(hand)
    
    return events, event_types

def update_dashboard_data():
    """Update dashboard data with latest information."""
    try:
        # Get system information
        system_info = get_system_info()
        
        # Get Sysmon events
        events, event_types = get_sysmon_events(100)
        
        # Update dashboard data
        dashboard_data.events = events
        dashboard_data.metrics = {
            'system': system_info,
            'events': {
                'total': len(events),
                'by_type': event_types,
                'by_severity': {
                    'high': len([e for e in events if e['level'] == 'high']),
                    'medium': len([e for e in events if e['level'] == 'medium']),
                    'low': len([e for e in events if e['level'] == 'low'])
                }
            },
            'performance': {
                'cpu': system_info['cpu_percent'],
                'memory': system_info['memory_percent'],
                'disk': system_info['disk_percent'],
                'network': 0  # Network monitoring would go here
            }
        }
        dashboard_data.last_updated = datetime.now()
        
    except Exception as e:
        logger.error(f"Error updating dashboard data: {e}")

# Routes
@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Unified SIEM Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            .event-high { border-left: 4px solid #ef4444; }
            .event-medium { border-left: 4px solid #f59e0b; }
            .event-low { border-left: 4px solid #3b82f6; }
            .card {
                transition: all 0.3s ease;
                height: 100%;
            }
            .card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 1rem;
                margin-bottom: 1rem;
            }
            .event-card {
                transition: all 0.2s ease;
            }
            .event-card:hover {
                background-color: #f9fafb;
            }
        </style>
    </head>
    <body class="bg-gray-100">
        <!-- Header -->
        <header class="bg-gray-900 text-white shadow-lg">
            <div class="container mx-auto px-4 py-4">
                <div class="flex justify-between items-center">
                    <div class="flex items-center space-x-3">
                        <i class="fas fa-shield-alt text-blue-400 text-2xl"></i>
                        <h1 class="text-2xl font-bold">Unified SIEM Dashboard</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-sm text-gray-300">Last updated: <span id="last-updated">Just now</span></span>
                        <button onclick="refreshData()" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm flex items-center">
                            <i class="fas fa-sync-alt mr-1"></i> Refresh
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <div class="container mx-auto px-4 py-6">
            <!-- Stats Overview -->
            <div class="dashboard-grid">
                <!-- Total Events -->
                <div class="bg-white rounded-lg shadow p-6 card">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-blue-100 text-blue-600 mr-4">
                            <i class="fas fa-chart-bar text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Total Events</p>
                            <h3 class="text-2xl font-bold" id="total-events">0</h3>
                        </div>
                    </div>
                </div>

                <!-- High Severity -->
                <div class="bg-white rounded-lg shadow p-6 card">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-red-100 text-red-600 mr-4">
                            <i class="fas fa-exclamation-triangle text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">High Severity</p>
                            <h3 class="text-2xl font-bold" id="high-severity">0</h3>
                        </div>
                    </div>
                </div>

                <!-- CPU Usage -->
                <div class="bg-white rounded-lg shadow p-6 card">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-purple-100 text-purple-600 mr-4">
                            <i class="fas fa-microchip text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">CPU Usage</p>
                            <h3 class="text-2xl font-bold" id="cpu-usage">0%</h3>
                        </div>
                    </div>
                </div>

                <!-- Memory Usage -->
                <div class="bg-white rounded-lg shadow p-6 card">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-green-100 text-green-600 mr-4">
                            <i class="fas fa-memory text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Memory Usage</p>
                            <h3 class="text-2xl font-bold" id="memory-usage">0%</h3>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
                <!-- Events List -->
                <div class="lg:col-span-2">
                    <div class="bg-white rounded-lg shadow overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200">
                            <h2 class="text-lg font-semibold text-gray-800">Recent Security Events</h2>
                        </div>
                        <div class="divide-y divide-gray-200" id="events-list" style="max-height: 600px; overflow-y: auto;">
                            <div class="p-4 text-center text-gray-500">
                                <i class="fas fa-spinner fa-spin mr-2"></i> Loading events...
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Info -->
                <div class="space-y-6">
                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-lg font-semibold text-gray-800 mb-4">System Information</h2>
                        <div class="space-y-2 text-sm" id="system-info">
                            <div class="flex justify-between">
                                <span class="text-gray-500">Hostname:</span>
                                <span id="hostname">Loading...</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">OS:</span>
                                <span id="os-info">Loading...</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Uptime:</span>
                                <span id="uptime">Loading...</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Disk Usage:</span>
                                <span id="disk-usage">Loading...</span>
                            </div>
                        </div>
                    </div>

                    <!-- Event Types -->
                    <div class="bg-white rounded-lg shadow p-6">
                        <h2 class="text-lg font-semibold text-gray-800 mb-4">Event Types</h2>
                        <div class="space-y-2" id="event-types">
                            <div class="flex items-center justify-between">
                                <div class="w-3/4">
                                    <div class="h-2 bg-gray-200 rounded-full overflow-hidden">
                                        <div class="h-full bg-blue-500 rounded-full" style="width: 0%" id="event-type-1"></div>
                                    </div>
                                </div>
                                <span class="text-sm text-gray-500 ml-2" id="event-type-1-label">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Global variables
            let eventTypesChart;

            // Format bytes to human-readable format
            function formatBytes(bytes, decimals = 2) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const dm = decimals < 0 ? 0 : decimals;
                const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
            }

            // Format time duration
            function formatUptime(seconds) {
                const days = Math.floor(seconds / 86400);
                const hours = Math.floor((seconds % 86400) / 3600);
                const mins = Math.floor((seconds % 3600) / 60);
                return `${days}d ${hours}h ${mins}m`;
            }

            // Update the dashboard with new data
            function updateDashboard(data) {
                // Update last updated time
                document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
                
                // Update stats
                document.getElementById('total-events').textContent = data.metrics.events.total;
                document.getElementById('high-severity').textContent = data.metrics.events.by_severity.high || 0;
                document.getElementById('cpu-usage').textContent = `${data.metrics.performance.cpu}%`;
                document.getElementById('memory-usage').textContent = `${data.metrics.performance.memory}%`;
                
                // Update system info
                const sysInfo = data.metrics.system;
                document.getElementById('hostname').textContent = sysInfo.node || 'N/A';
                document.getElementById('os-info').textContent = `${sysInfo.system} ${sysInfo.release}`.trim();
                document.getElementById('uptime').textContent = sysInfo.uptime || 'N/A';
                document.getElementById('disk-usage').textContent = `${sysInfo.disk_percent}%`;
                
                // Update events list
                const eventsList = document.getElementById('events-list');
                if (data.events && data.events.length > 0) {
                    eventsList.innerHTML = data.events.map(event => `
                        <div class="event-card p-4 hover:bg-gray-50 event-${event.level}">
                            <div class="flex justify-between items-start">
                                <div class="flex-1">
                                    <div class="flex items-center mb-1">
                                        <span class="font-semibold text-gray-900 mr-2">${event.source}</span>
                                        <span class="text-xs px-2 py-1 rounded-full ${
                                            event.level === 'high' ? 'bg-red-100 text-red-800' : 
                                            event.level === 'medium' ? 'bg-yellow-100 text-yellow-800' : 
                                            'bg-blue-100 text-blue-800'
                                        }">
                                            Event ${event.event_id} (${event.level})
                                        </span>
                                    </div>
                                    <div class="text-sm text-gray-600 mb-2">
                                        ${event.data ? event.data.join('<br>') : 'No data'}
                                    </div>
                                    <div class="text-xs text-gray-400">
                                        <i class="far fa-clock mr-1"></i> ${event.timestamp}
                                        <span class="mx-2">•</span>
                                        <i class="fas fa-desktop mr-1"></i> ${event.computer}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }
                
                // Update event types
                const eventTypes = data.metrics.events.by_type;
                const eventTypesContainer = document.getElementById('event-types');
                let eventTypesHtml = '';
                
                Object.entries(eventTypes).forEach(([type, count], index) => {
                    const percentage = (count / data.metrics.events.total) * 100;
                    eventTypesHtml += `
                        <div class="mb-2">
                            <div class="flex justify-between text-sm mb-1">
                                <span class="text-gray-700">${type}</span>
                                <span class="font-medium">${count}</span>
                            </div>
                            <div class="h-2 bg-gray-200 rounded-full overflow-hidden">
                                <div class="h-full rounded-full ${
                                    index % 3 === 0 ? 'bg-blue-500' : 
                                    index % 3 === 1 ? 'bg-green-500' : 'bg-purple-500'
                                }" style="width: ${percentage}%"></div>
                            </div>
                        </div>
                    `;
                });
                
                eventTypesContainer.innerHTML = eventTypesHtml || '<p class="text-gray-500 text-sm">No event data available</p>';
            }

            // Fetch data from the server
            async function fetchData() {
                try {
                    const response = await fetch('/api/dashboard');
                    const data = await response.json();
                    updateDashboard(data);
                } catch (error) {
                    console.error('Error fetching data:', error);
                }
            }

            // Manual refresh
            function refreshData() {
                const btn = document.querySelector('button[onclick="refreshData()"]');
                const icon = btn.querySelector('i');
                
                // Add spin animation
                icon.classList.add('fa-spin');
                
                // Update data
                fetchData().finally(() => {
                    // Remove spin animation after a short delay
                    setTimeout(() => {
                        icon.classList.remove('fa-spin');
                    }, 500);
                });
            }

            // Initialize the dashboard
            document.addEventListener('DOMContentLoaded', () => {
                // Initial data load
                fetchData();
                
                // Refresh data every 5 seconds
                setInterval(fetchData, 5000);
            });
        </script>
    </body>
    </html>
    ''')

@app.route('/api/dashboard')
def get_dashboard_data():
    """API endpoint to get dashboard data."""
    update_dashboard_data()
    return jsonify({
        'events': dashboard_data.events,
        'metrics': dashboard_data.metrics,
        'last_updated': dashboard_data.last_updated.isoformat()
    })

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('static', path)

if __name__ == '__main__':
    # Initial data load
    update_dashboard_data()
    
    # Start the web server
    app.run(host='0.0.0.0', port=5000, debug=True)
