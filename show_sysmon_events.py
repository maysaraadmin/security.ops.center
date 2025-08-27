"""
Script to fetch and display Sysmon events in the SIEM web interface.
"""
import os
import sys
import time
import json
from datetime import datetime, timedelta
import win32evtlog
import win32con
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# In-memory storage for events (in a real app, use a database)
events = []

def get_sysmon_events():
    """Fetch Sysmon events from Windows Event Log."""
    try:
        # Connect to the Sysmon log
        hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        # Get recent events (last 50)
        events = []
        count = 0
        max_events = 50
        
        while count < max_events:
            results = win32evtlog.ReadEventLog(hand, flags, 0)
            if not results:
                break
                
            for event in results:
                if count >= max_events:
                    break
                    
                event_data = {
                    'timestamp': event.TimeGenerated.Format(),
                    'event_id': event.EventID,
                    'source': event.SourceName,
                    'computer': event.ComputerName,
                    'data': []
                }
                
                # Extract event data
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

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SIEM - Sysmon Events</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            background: #2c3e50; 
            color: white; 
            padding: 20px; 
            border-radius: 5px; 
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .refresh-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
        }
        .refresh-btn:hover { background: #2980b9; }
        .event-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(500px, 1fr));
            gap: 15px;
        }
        .event-card {
            background: white;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .event-header {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
            margin-bottom: 10px;
        }
        .event-id { 
            font-weight: bold;
            color: #e74c3c;
        }
        .event-time { color: #7f8c8d; font-size: 0.9em; }
        .event-data { 
            font-family: monospace; 
            white-space: pre-wrap;
            font-size: 0.9em;
            line-height: 1.4;
        }
        .no-events { 
            text-align: center; 
            padding: 20px; 
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SIEM - Sysmon Events</h1>
            <a href="/" class="refresh-btn">Refresh</a>
        </div>
        
        <div class="event-grid">
            {% if events %}
                {% for event in events %}
                <div class="event-card">
                    <div class="event-header">
                        <span class="event-id">Event ID: {{ event.event_id }}</span>
                        <span class="event-time">{{ event.timestamp }}</span>
                    </div>
                    <div class="event-source">Source: {{ event.source }}</div>
                    <div class="event-computer">Computer: {{ event.computer }}</div>
                    <div class="event-data">
                        {{ event.data | join('\n') }}
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="no-events">No Sysmon events found or Sysmon is not installed.</div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Render the Sysmon events page."""
    events = get_sysmon_events()
    return render_template_string(HTML_TEMPLATE, events=events)

@app.route('/api/events')
def api_events():
    """API endpoint to get Sysmon events as JSON."""
    events = get_sysmon_events()
    return jsonify(events)

if __name__ == '__main__':
    print("Starting SIEM Sysmon Viewer on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
