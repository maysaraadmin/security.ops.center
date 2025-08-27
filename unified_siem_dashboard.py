"""
Unified SIEM Dashboard
A comprehensive dashboard for monitoring security events and system metrics.
"""
from flask import Flask, render_template_string, jsonify
import psutil
import platform
import datetime
import os
import sys
import win32evtlog
import win32con
import win32api
import winerror
import traceback

app = Flask(__name__)

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Unified SIEM Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <style>
        .event-high { border-left: 4px solid #ef4444; }
        .event-medium { border-left: 4px solid #f59e0b; }
        .event-low { border-left: 4px solid #3b82f6; }
        .filter-section { transition: all 0.3s ease; }
        .filter-section.collapsed { max-height: 0; opacity: 0; overflow: hidden; }
        .event-details { display: none; }
        .event-details.active { display: block; }
        #eventChart { max-height: 300px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-6">
        <div class="flex justify-between items-center mb-6">
            <h1 class="text-2xl font-bold">Unified SIEM Dashboard</h1>
            <div class="flex space-x-2">
                <button onclick="toggleFilters()" class="px-3 py-1 bg-blue-100 text-blue-700 rounded text-sm">
                    <i class="fas fa-filter mr-1"></i> Filters
                </button>
                <button onclick="location.reload()" class="px-3 py-1 bg-gray-100 text-gray-700 rounded text-sm">
                    <i class="fas fa-sync-alt mr-1"></i> Refresh
                </button>
            </div>
        </div>
        
        <!-- Status Bar -->
        <div class="bg-white rounded-lg shadow p-4 mb-6">
            <div class="flex justify-between items-center">
                <div class="flex items-center space-x-4">
                    <div>
                        <span class="font-semibold">Status:</span>
                        <span class="text-green-600 ml-2">Running</span>
                    </div>
                    <div class="text-sm text-gray-500">
                        Events: <span class="font-medium">{{ events_summary.total }}</span>
                        (<span class="text-red-600">{{ events_summary.high }}</span>/
                        <span class="text-yellow-600">{{ events_summary.medium }}</span>/
                        <span class="text-blue-600">{{ events_summary.low }}</span>)
                    </div>
                </div>
                <div class="text-sm text-gray-500">
                    Last updated: <span id="last-updated">{{ now.strftime('%Y-%m-%d %H:%M:%S') }}</span>
                </div>
            </div>
        </div>
        
        <!-- Filters Section -->
        <div id="filters" class="filter-section bg-white rounded-lg shadow p-4 mb-6">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <!-- Event Type Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Event Type</label>
                    <select id="event-type" class="w-full p-2 border rounded">
                        <option value="">All Events</option>
                        <option value="1">Process Create (1)</option>
                        <option value="3">Network Connect (3)</option>
                        <option value="7">Image Loaded (7)</option>
                        <option value="8">CreateRemoteThread (8)</option>
                        <option value="10">Process Access (10)</option>
                        <option value="11">File Create (11)</option>
                    </select>
                </div>
                
                <!-- Severity Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                    <select id="severity" class="w-full p-2 border rounded">
                        <option value="">All Levels</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                
                <!-- Time Range -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Time Range</label>
                    <input type="text" id="time-range" class="w-full p-2 border rounded" placeholder="Select time range">
                </div>
                
                <!-- Search -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Search</label>
                    <input type="text" id="search" class="w-full p-2 border rounded" placeholder="Search events...">
                </div>
            </div>
            
            <div class="mt-4 flex justify-end space-x-2">
                <button onclick="applyFilters()" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                    Apply Filters
                </button>
                <button onclick="resetFilters()" class="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300">
                    Reset
                </button>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="mb-4 border-b border-gray-200">
            <ul class="flex flex-wrap -mb-px" id="dashboard-tabs">
                <li class="mr-2">
                    <a href="#events" class="tab-link inline-block p-4 border-b-2 border-blue-600 rounded-t-lg text-blue-600 active" data-tab="events">
                        <i class="fas fa-list-ul mr-2"></i>Events
                    </a>
                </li>
                <li class="mr-2">
                    <a href="#analytics" class="tab-link inline-block p-4 border-b-2 border-transparent rounded-t-lg hover:text-gray-600 hover:border-gray-300" data-tab="analytics">
                        <i class="fas fa-chart-bar mr-2"></i>Analytics
                    </a>
                </li>
                <li class="mr-2">
                    <a href="#processes" class="tab-link inline-block p-4 border-b-2 border-transparent rounded-t-lg hover:text-gray-600 hover:border-gray-300" data-tab="processes">
                        <i class="fas fa-project-diagram mr-2"></i>Processes
                    </a>
                </li>
                <li>
                    <a href="#network" class="tab-link inline-block p-4 border-b-2 border-transparent rounded-t-lg hover:text-gray-600 hover:border-gray-300" data-tab="network">
                        <i class="fas fa-network-wired mr-2"></i>Network
                    </a>
                </li>
            </ul>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <!-- System Info Card -->
            <div class="bg-white rounded-lg shadow p-4">
                <h3 class="font-semibold mb-2">System Information</h3>
                <div class="text-sm space-y-1">
                    <div>OS: {{ system_info.os }}</div>
                    <div>CPU: {{ system_info.cpu }}%</div>
                    <div>Memory: {{ system_info.memory }}%</div>
                    <div>Disk: {{ system_info.disk }}%</div>
                </div>
            </div>

            <!-- Events Summary -->
            <div class="bg-white rounded-lg shadow p-4">
                <h3 class="font-semibold mb-2">Events Summary</h3>
                <div class="text-sm space-y-1">
                    <div>Total Events: {{ events_summary.total }}</div>
                    <div class="text-red-600">High: {{ events_summary.high }}</div>
                    <div class="text-yellow-600">Medium: {{ events_summary.medium }}</div>
                    <div class="text-blue-600">Low: {{ events_summary.low }}</div>
                </div>
            </div>
        </div>

        <!-- Events Table -->
        <div class="bg-white rounded-lg shadow overflow-hidden">
            <div class="px-6 py-4 border-b">
                <h2 class="text-lg font-semibold">Recent Security Events</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event ID</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                        </tr>
                    </thead>
                    <tbody id="events-body" class="bg-white divide-y divide-gray-200">
                        {% for event in events %}
                        <tr class="event-{{ event.level }} hover:bg-gray-50">
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ event.timestamp }}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                    {{ 'bg-red-100 text-red-800' if event.level == 'high' else 
                                       'bg-yellow-100 text-yellow-800' if event.level == 'medium' else 
                                       'bg-blue-100 text-blue-800' }}">
                                    {{ event.event_id }}
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ event.source }}</td>
                            <td class="px-6 py-4 text-sm text-gray-500">
                                {{ event.details }}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Auto-refresh the page every 5 seconds
        setTimeout(function() {
            window.location.reload();
        }, 5000);

        // Update last updated time
        function updateLastUpdated() {
            const now = new Date();
            document.getElementById('last-updated').textContent = now.toLocaleTimeString();
        }
        
        updateLastUpdated();
        setInterval(updateLastUpdated, 1000);
    </script>
</body>
</html>
"""

def get_system_info():
    """Get system information."""
    return {
        'os': f"{platform.system()} {platform.release()}",
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent
    }

def get_sysmon_events(limit=100):
    """Fetch Sysmon events from Windows Event Log."""
    events = []
    
    try:
        # Try to open the Sysmon event log
        try:
            hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        except Exception as e:
            if 'The system cannot find the file specified' in str(e):
                print("Sysmon log not found. Make sure Sysmon is installed.")
                return get_sample_events()
            raise
            
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        count = 0
        while count < limit:
            try:
                events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events_batch:
                    break
                    
                for event in events_batch:
                    if count >= limit:
                        break
                        
                    # Skip if event data is not available
                    if not hasattr(event, 'StringInserts') or not event.StringInserts:
                        continue
                        
                    # Determine event level based on ID
                    event_id = event.EventID
                    if event_id in [1, 8, 10]:  # Critical events
                        level = 'high'
                    elif event_id in [3, 11, 12, 13, 14]:  # Important events
                        level = 'medium'
                    else:  # Informational events
                        level = 'low'
                    
                    # Format event details
                    details = []
                    for i, item in enumerate(event.StringInserts):
                        if item:  # Only include non-empty strings
                            details.append(f"{i+1}. {str(item).strip()}")
                    
                    # Add the event to our list
                    events.append({
                        'timestamp': event.TimeGenerated.Format(),
                        'event_id': event_id,
                        'source': event.SourceName,
                        'level': level,
                        'details': '\n'.join(details) if details else 'No details available'
                    })
                    
                    count += 1
                    
            except Exception as e:
                print(f"Error reading event: {e}")
                break
                
    except Exception as e:
        print(f"Error accessing event log: {e}")
        traceback.print_exc()
        return get_sample_events()
        
    finally:
        if 'hand' in locals():
            win32evtlog.CloseEventLog(hand)
    
    # If no events found, return sample data
    if not events:
        print("No Sysmon events found. Using sample data.")
        return get_sample_events()
        
    return events

def get_sample_events():
    """Generate sample events for demonstration when real events are not available."""
    return [
        {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': 1,
            'source': 'Microsoft-Windows-Sysmon',
            'level': 'high',
            'details': '1. Process Create\n2. C:\\Windows\\System32\\cmd.exe'
        },
        {
            'timestamp': (datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': 3,
            'source': 'Microsoft-Windows-Sysmon',
            'level': 'medium',
            'details': '1. Network connection detected\n2. Destination: example.com\n3. Port: 443'
        },
        {
            'timestamp': (datetime.datetime.now() - datetime.timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S'),
            'event_id': 11,
            'source': 'Microsoft-Windows-Sysmon',
            'level': 'medium',
            'details': '1. File created\n2. C:\\temp\\suspicious.exe'
        }
    ]

@app.route('/')
def index():
    """Render the main dashboard."""
    system_info = get_system_info()
    
    try:
        # Try to get real Sysmon events
        events = get_sysmon_events(50)  # Get last 50 events
    except Exception as e:
        print(f"Error getting Sysmon events: {e}")
        traceback.print_exc()
        events = get_sample_events()
    
    # Calculate event summary
    events_summary = {
        'total': len(events),
        'high': len([e for e in events if e['level'] == 'high']),
        'medium': len([e for e in events if e['level'] == 'medium']),
        'low': len([e for e in events if e['level'] == 'low'])
    }
    
    return render_template_string(
        HTML_TEMPLATE,
        system_info=system_info,
        events_summary=events_summary,
        events=events
    )

@app.route('/api/events')
def get_events():
    """API endpoint to get events."""
    try:
        events = get_sysmon_events(50)
    except Exception as e:
        print(f"Error in API endpoint: {e}")
        events = get_sample_events()
        
    return jsonify({
        'system': get_system_info(),
        'events': events,
        'timestamp': datetime.datetime.now().isoformat()
    })

def check_sysmon_installed():
    """Check if Sysmon is installed by looking for its event log."""
    try:
        hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        win32evtlog.CloseEventLog(hand)
        return True
    except:
        return False

if __name__ == '__main__':
    print("Starting Unified SIEM Dashboard...")
    
    # Check if Sysmon is installed
    if not check_sysmon_installed():
        print("\nWARNING: Sysmon is not installed or not properly configured.")
        print("The dashboard will show sample data instead of real events.")
        print("To enable real Sysmon events, please install Sysmon from:")
        print("https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon\n")
    
    print("\nPlease open http://localhost:5000 in your web browser")
    print("Press Ctrl+C to stop the server\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except Exception as e:
        print(f"Error starting server: {e}")
        if "Address already in use" in str(e):
            print("\nError: Port 5000 is already in use.")
            print("Please close any other applications using this port or use a different port.")
        sys.exit(1)
