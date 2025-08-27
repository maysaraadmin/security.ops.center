"""
Enhanced SIEM Dashboard with Sysmon Events
"""
import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta
import win32evtlog
import win32con
from flask import Flask, render_template_string, jsonify, Response
from flask_socketio import SocketIO, emit
import psutil
import platform

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage for events (in production, use a database)
events = []
stats = {
    'total_events': 0,
    'event_types': {},
    'sources': {},
    'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'host_info': {}
}

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

def get_sysmon_events(limit=100):
    """Fetch Sysmon events from Windows Event Log."""
    try:
        hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events = []
        count = 0
        
        while count < limit:
            results = win32evtlog.ReadEventLog(hand, flags, 0)
            if not results:
                break
                
            for event in results:
                if count >= limit:
                    break
                    
                event_data = {
                    'id': count + 1,
                    'timestamp': event.TimeGenerated.Format(),
                    'event_id': event.EventID,
                    'source': event.SourceName,
                    'computer': event.ComputerName,
                    'level': 'info',
                    'data': []
                }
                
                # Add event type to stats
                event_type = f'Event {event.EventID}'
                stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
                
                # Add source to stats
                stats['sources'][event.SourceName] = stats['sources'].get(event.SourceName, 0) + 1
                
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
                
        return events
        
    except Exception as e:
        print(f"Error reading Sysmon events: {e}")
        return []
    finally:
        if 'hand' in locals():
            win32evtlog.CloseEventLog(hand)

def background_thread():
    """Background thread to update events periodically."""
    global events, stats
    
    while True:
        try:
            new_events = get_sysmon_events(50)  # Get last 50 events
            if new_events:
                events = new_events
                stats['total_events'] = len(events)
                stats['host_info'] = get_system_info()
                
                # Emit update to all connected clients
                socketio.emit('update', {
                    'events': events[-10:],  # Send only the 10 most recent events
                    'stats': stats
                })
                
        except Exception as e:
            print(f"Error in background thread: {e}")
            
        time.sleep(5)  # Update every 5 seconds

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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        .event-warning { border-left: 4px solid #f59e0b; }
        .event-info { border-left: 4px solid #3b82f6; }
        .event-debug { border-left: 4px solid #6b7280; }
        .blink {
            animation: blinker 1s linear infinite;
        }
        @keyframes blinker {
            50% { opacity: 0.5; }
        }
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
                <button onclick="location.reload()" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
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

            <!-- Event Types Chart -->
            <div class="space-y-6">
                <div class="bg-white rounded-lg shadow p-6">
                    <h2 class="text-lg font-semibold text-gray-800 mb-4">Event Types</h2>
                    <div class="h-64">
                        <canvas id="eventTypesChart"></canvas>
                    </div>
                </div>

                <!-- System Info -->
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
                            <span class="text-gray-500">Uptime:</span>
                            <span id="uptime">Loading...</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Connect to WebSocket
        const socket = io();
        
        // Event Types Chart
        const eventTypesCtx = document.getElementById('eventTypesChart').getContext('2d');
        const eventTypesChart = new Chart(eventTypesCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#3b82f6', '#10b981', '#f59e0b', '#ef4444',
                        '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Update dashboard with new data
        socket.on('update', function(data) {
            // Update last updated time
            document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
            
            // Update stats
            document.getElementById('total-events').textContent = data.stats.total_events;
            document.getElementById('event-types').textContent = Object.keys(data.stats.event_types).length;
            
            // Update system info
            if (data.stats.host_info) {
                const hi = data.stats.host_info;
                document.getElementById('host-name').textContent = hi.node || 'N/A';
                document.getElementById('os-info').textContent = `${hi.system || ''} ${hi.release || ''}`.trim();
                document.getElementById('cpu-usage').textContent = `${hi.cpu_percent || 0}%`;
                document.getElementById('memory-usage').textContent = `${hi.memory_percent || 0}%`;
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
            
            // Update event types chart
            if (data.stats.event_types) {
                const eventTypes = Object.entries(data.stats.event_types)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5);
                
                eventTypesChart.data.labels = eventTypes.map(e => e[0]);
                eventTypesChart.data.datasets[0].data = eventTypes.map(e => e[1]);
                eventTypesChart.update();
            }
        });

        // Handle errors
        socket.on('connect_error', (error) => {
            console.error('Connection Error:', error);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Render the SIEM dashboard."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/events')
def api_events():
    """API endpoint to get Sysmon events as JSON."""
    return jsonify({
        'events': events,
        'stats': stats
    })

if __name__ == '__main__':
    # Start background thread to update events
    thread = threading.Thread(target=background_thread, daemon=True)
    thread.start()
    
    # Get initial system info
    stats['host_info'] = get_system_info()
    
    print("Starting SIEM Dashboard on http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    # Start the Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)
