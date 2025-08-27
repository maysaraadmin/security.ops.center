"""
Simple SIEM Dashboard for Sysmon Events
"""
import os
import sys
import time
import json
from datetime import datetime
import win32evtlog
import win32con
import psutil
import platform
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)

# HTML template for the dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM Dashboard - Sysmon Events</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .event-warning { border-left: 4px solid #f59e0b; }
        .event-info { border-left: 4px solid #3b82f6; }
        .event-debug { border-left: 4px solid #6b7280; }
        .event-card {
            transition: all 0.3s ease;
        }
        .event-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
    </style>
</head>
<body class="bg-gray-100">
    <!-- Header -->
    <header class="bg-gray-900 text-white shadow-lg">
        <div class="container mx-auto px-4 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fas fa-shield-alt text-blue-400 text-2xl"></i>
                <h1 class="text-xl font-bold">SIEM Dashboard</h1>
            </div>
            <div class="flex items-center space-x-4">
                <span class="text-sm text-gray-300">Last updated: <span id="last-updated">Just now</span></span>
                <button onclick="refreshData()" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                    <i class="fas fa-sync-alt mr-1"></i> Refresh
                </button>
            </div>
        </div>
    </header>

    <div class="container mx-auto px-4 py-6">
        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            <!-- Total Events -->
            <div class="bg-white rounded-lg shadow p-6">
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

            <!-- Event Types -->
            <div class="bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="p-3 rounded-full bg-green-100 text-green-600 mr-4">
                        <i class="fas fa-tags text-xl"></i>
                    </div>
                    <div>
                        <p class="text-gray-500 text-sm">Event Types</p>
                        <h3 class="text-2xl font-bold" id="event-types">0</h3>
                    </div>
                </div>
            </div>

            <!-- System Status -->
            <div class="bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="p-3 rounded-full bg-purple-100 text-purple-600 mr-4">
                        <i class="fas fa-server text-xl"></i>
                    </div>
                    <div>
                        <p class="text-gray-500 text-sm">CPU Usage</p>
                        <h3 class="text-2xl font-bold" id="cpu-usage">0%</h3>
                    </div>
                </div>
            </div>

            <!-- Memory Usage -->
            <div class="bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="p-3 rounded-full bg-yellow-100 text-yellow-600 mr-4">
                        <i class="fas fa-memory text-xl"></i>
                    </div>
                    <div>
                        <p class="text-gray-500 text-sm">Memory Usage</p>
                        <h3 class="text-2xl font-bold" id="memory-usage">0%</h3>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Events List -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-lg shadow overflow-hidden">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h2 class="text-lg font-semibold text-gray-800">Recent Events</h2>
                    </div>
                    <div class="divide-y divide-gray-200" id="events-list" style="max-height: 600px; overflow-y: auto;">
                        <!-- Events will be inserted here by JavaScript -->
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
                            <span class="text-gray-500">Host:</span>
                            <span id="host-name">Loading...</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-500">OS:</span>
                            <span id="os-info">Loading...</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-500">CPU Usage:</span>
                            <span id="cpu-percent">Loading...</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-500">Memory Usage:</span>
                            <span id="mem-percent">Loading...</span>
                        </div>
                    </div>
                </div>
                
                <!-- Event Types -->
                <div class="bg-white rounded-lg shadow p-6">
                    <h2 class="text-lg font-semibold text-gray-800 mb-4">Event Types</h2>
                    <div id="event-types-list" class="space-y-2">
                        <!-- Event types will be inserted here -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Function to update the dashboard
        async function updateDashboard() {
            try {
                const response = await fetch('/api/events');
                const data = await response.json();
                
                // Update last updated time
                document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
                
                // Update stats
                document.getElementById('total-events').textContent = data.stats.total_events;
                document.getElementById('event-types').textContent = Object.keys(data.stats.event_types || {}).length;
                
                // Update system info
                if (data.stats.host_info) {
                    const hi = data.stats.host_info;
                    document.getElementById('host-name').textContent = hi.node || 'N/A';
                    document.getElementById('os-info').textContent = `${hi.system || ''} ${hi.release || ''}`.trim();
                    document.getElementById('cpu-usage').textContent = `${hi.cpu_percent || 0}%`;
                    document.getElementById('memory-usage').textContent = `${hi.memory_percent || 0}%`;
                    document.getElementById('cpu-percent').textContent = `${hi.cpu_percent || 0}%`;
                    document.getElementById('mem-percent').textContent = `${hi.memory_percent || 0}%`;
                }
                
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
                                            event.level === 'warning' ? 'bg-yellow-100 text-yellow-800' : 
                                            event.level === 'info' ? 'bg-blue-100 text-blue-800' : 
                                            'bg-gray-100 text-gray-800'
                                        }">
                                            Event ${event.event_id}
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
                                <div class="ml-4">
                                    <span class="inline-block w-3 h-3 rounded-full ${
                                        event.level === 'warning' ? 'bg-yellow-400' : 
                                        event.level === 'info' ? 'bg-blue-400' : 'bg-gray-400'
                                    }" title="${event.level}"></span>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }
                
                // Update event types list
                const eventTypesList = document.getElementById('event-types-list');
                if (data.stats.event_types) {
                    const sortedTypes = Object.entries(data.stats.event_types)
                        .sort((a, b) => b[1] - a[1]);
                    
                    eventTypesList.innerHTML = sortedTypes.map(([type, count]) => `
                        <div class="flex justify-between items-center">
                            <span class="text-gray-700">${type}</span>
                            <span class="px-2 py-1 text-xs rounded-full bg-gray-100">${count}</span>
                        </div>
                    `).join('');
                }
                
            } catch (error) {
                console.error('Error updating dashboard:', error);
            }
        }
        
        // Manual refresh function
        function refreshData() {
            const btn = event.target.closest('button');
            const icon = btn.querySelector('i');
            
            // Add spin animation
            icon.classList.add('fa-spin');
            
            // Update data
            updateDashboard().finally(() => {
                // Remove spin animation after a short delay
                setTimeout(() => {
                    icon.classList.remove('fa-spin');
                }, 500);
            });
        }
        
        // Initial load
        document.addEventListener('DOMContentLoaded', () => {
            updateDashboard();
            // Refresh every 5 seconds
            setInterval(updateDashboard, 5000);
        });
    </script>
</body>
</html>
"""

def get_system_info():
    """Get system information."""
    return {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'cpu_percent': psutil.cpu_percent(),
        'memory_percent': psutil.virtual_memory().percent,
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
    }

def get_sysmon_events(limit=50):
    """Fetch Sysmon events from Windows Event Log."""
    try:
        hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events = []
        count = 0
        event_types = {}
        
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
                
                # Set event level based on ID (customize as needed)
                if event.EventID in [1, 8, 10]:  # Process creation, CreateRemoteThread, ProcessAccess
                    event_data['level'] = 'warning'
                elif event.EventID in [3, 11, 12, 13, 14]:  # Network connection, File create, Registry events
                    event_data['level'] = 'info'
                else:
                    event_data['level'] = 'debug'
                
                if event.StringInserts:
                    event_data['data'] = [str(item) for item in event.StringInserts]
                
                events.append(event_data)
                count += 1
                
        return {
            'events': events,
            'stats': {
                'total_events': len(events),
                'event_types': event_types,
                'host_info': get_system_info()
            }
        }
        
    except Exception as e:
        print(f"Error reading Sysmon events: {e}")
        return {
            'events': [],
            'stats': {
                'total_events': 0,
                'event_types': {},
                'host_info': get_system_info(),
                'error': str(e)
            }
        }
    finally:
        if 'hand' in locals():
            win32evtlog.CloseEventLog(hand)

@app.route('/')
def index():
    """Render the SIEM dashboard."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/events')
def api_events():
    """API endpoint to get Sysmon events as JSON."""
    return jsonify(get_sysmon_events())

if __name__ == '__main__':
    print("Starting SIEM Dashboard on http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(host='0.0.0.0', port=5000, debug=True)
