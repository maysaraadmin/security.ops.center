"""
Unified SIEM Dashboard

A comprehensive dashboard that combines all SIEM monitoring and management features.
"""
import os
import sys
import json
import logging
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_from_directory, session, flash, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from functools import wraps
import os
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

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')

# Load configuration
app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-this-in-production'),
    PERMANENT_SESSION_LIFETIME=3600  # 1 hour session lifetime
)

# Initialize extensions
CORS(app)
# Use 'threading' async_mode for better compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Import and initialize authentication
from siem.auth import login_required, role_required, init_auth, login, logout

# Register authentication routes
app.add_url_rule('/login', 'login', login, methods=['GET', 'POST'])
app.add_url_rule('/logout', 'logout', logout)

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

# Initialize dashboard data
dashboard_data = DashboardData()

# Utility Functions
def get_system_info():
    """Collect system information."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu': cpu_percent,
            'memory': memory.percent,
            'disk': disk.percent,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            'os': f"{platform.system()} {platform.release()}",
            'hostname': platform.node(),
            'python': platform.python_version()
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {}

def get_sysmon_events(limit=100):
    """Fetch Sysmon events from Windows Event Log."""
    events = []
    hand = None
    
    try:
        # Try to open Sysmon log
        try:
            hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Sysmon/Operational')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            try:
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                logger.info(f"Found {total} Sysmon events in the log")
            except Exception as e:
                logger.warning(f"Could not get total number of events: {e}")
                total = 0
                
            events_read = 0
            while events_read < limit:
                try:
                    events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events_batch:
                        break
                        
                    for event in events_batch:
                        if events_read >= limit:
                            break
                            
                        try:
                            event_time = event.TimeGenerated
                            event_data = {
                                'event_id': event.EventID,
                                'time_generated': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                                'source_name': 'Sysmon',
                                'level': 'low',
                                'message': event.StringInserts[0] if event.StringInserts and len(event.StringInserts) > 0 else 'No message',
                                'data': [str(item) for item in event.StringInserts] if event.StringInserts else []
                            }
                            
                            # Set severity based on event ID
                            if event.EventID in [1, 5, 7, 8, 10, 11]:
                                event_data['level'] = 'high'
                            elif event.EventID in [2, 3, 12, 13, 14, 15]:
                                event_data['level'] = 'medium'
                                
                            events.append(event_data)
                            events_read += 1
                            
                        except Exception as e:
                            logger.warning(f"Error processing event: {e}")
                            continue
                            
                except Exception as e:
                    logger.error(f"Error reading events: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Could not open Sysmon event log: {e}")
            
            # Fallback to sample data if Sysmon is not available
            logger.info("Generating sample event data")
            event_types = ['Process Create', 'Network Connect', 'File Create', 'Registry Event']
            for i in range(min(limit, 10)):  # Limit to 10 sample events
                event_time = datetime.now() - timedelta(minutes=i)
                events.append({
                    'event_id': random.choice([1, 3, 5, 7, 10, 11]),
                    'time_generated': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'source_name': 'Sample Data',
                    'level': random.choice(['low', 'medium', 'high']),
                    'message': f"Sample {random.choice(event_types)} event",
                    'data': [f"Sample {random.choice(event_types)} event", f"Details {i+1}"]
                })
                
    except Exception as e:
        logger.error(f"Unexpected error in get_sysmon_events: {e}")
        
        # Generate some sample data in case of any error
        event_types = ['Process Create', 'Network Connect', 'File Create', 'Registry Event']
        for i in range(min(limit, 5)):  # Generate 5 sample events
            event_time = datetime.now() - timedelta(minutes=i)
            events.append({
                'event_id': random.choice([1, 3, 5, 7, 10, 11]),
                'time_generated': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                'source_name': 'Sample Data',
                'level': random.choice(['low', 'medium', 'high']),
                'message': f"Sample {random.choice(event_types)} event",
                'data': [f"Sample {random.choice(event_types)} event", f"Details {i+1}"]
            })
    finally:
        if hand:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                logger.error(f"Error closing event log: {e}")
    
    return events

def update_dashboard_data():
    """Update dashboard data with latest information."""
    try:
        # Update system metrics
        dashboard_data.metrics['system'] = get_system_info()
        
        # Get latest events
        events = get_sysmon_events(limit=50)
        dashboard_data.events = events
        
        # Update event statistics
        dashboard_data.metrics['events']['total'] = len(events)
        
        # Count events by type and severity
        type_counts = {}
        severity_counts = {}
        
        for event in events:
            event_type = event.get('source_name', 'unknown')
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            
            # Map event IDs to severity levels (simplified)
            event_id = str(event.get('event_id', 0))
            if event_id in ['1', '5', '7', '8', '10', '11']:
                severity = 'high'
            elif event_id in ['2', '3', '12', '13', '14', '15']:
                severity = 'medium'
            else:
                severity = 'low'
                
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        dashboard_data.metrics['events']['by_type'] = type_counts
        dashboard_data.metrics['events']['by_severity'] = severity_counts
        dashboard_data.last_updated = datetime.now()
        
    except Exception as e:
        logger.error(f"Error updating dashboard data: {e}")

# Background thread to update data
def background_thread():
    """Background thread to update dashboard data periodically."""
    while True:
        try:
            update_dashboard_data()
            # Emit update to all connected clients
            socketio.emit('data_update', {
                'metrics': dashboard_data.metrics,
                'last_updated': dashboard_data.last_updated.isoformat()
            })
            socketio.sleep(5)  # Update every 5 seconds
        except Exception as e:
            logger.error(f"Error in background thread: {e}")
            socketio.sleep(10)  # Wait longer on error

# Authentication required decorator for SocketIO
def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('username'):
            emit('redirect', {'url': url_for('login')})
            return
        return f(*args, **kwargs)
    return wrapped

# Routes
@app.route('/')
@login_required
def index():
    """Render the main dashboard."""
    try:
        # Get latest events
        events = get_sysmon_events(limit=50)
        
        # Ensure events is a list
        if not isinstance(events, list):
            logger.error(f"Expected events to be a list, got {type(events)}")
            events = []
            
        # Get system info
        system_info = get_system_info()
        
        # Count events by type and severity
        event_types = {}
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for event in events:
            try:
                # Ensure event is a dictionary
                if not isinstance(event, dict):
                    logger.warning(f"Skipping invalid event: {event}")
                    continue
                    
                # Count by type
                event_type = f"Event {event.get('event_id', 'unknown')}"
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                # Count by severity
                severity = str(event.get('level', 'low')).lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    
            except Exception as e:
                logger.error(f"Error processing event {event}: {e}")
                continue
        
        # Update dashboard metrics
        dashboard_data.metrics = {
            'system': system_info,
            'events': {
                'total': len(events),
                'by_type': event_types,
                'by_severity': severity_counts
            },
            'performance': {
                'cpu': system_info.get('cpu', 0),
                'memory': system_info.get('memory', 0),
                'disk': system_info.get('disk', 0),
                'network': 0
            }
        }
        
        return render_template('dashboard/index.html', 
                            events=events[-20:],  # Show only last 20 events
                            metrics=dashboard_data.metrics,
                            username=session.get('username'),
                            role=session.get('role'))
                            
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        # Return a basic response even if there's an error
        return render_template('dashboard/index.html',
                            events=[],
                            metrics={
                                'system': {},
                                'events': {'total': 0, 'by_type': {}, 'by_severity': {'high': 0, 'medium': 0, 'low': 0}},
                                'performance': {'cpu': 0, 'memory': 0, 'disk': 0, 'network': 0}
                            },
                            username=session.get('username'),
                            role=session.get('role'))

@app.route('/api/events')
@login_required
def api_events():
    """API endpoint to get events as JSON."""
    # For demo purposes, limit some data for non-admin users
    response_data = {
        'events': dashboard_data.events,
        'metrics': dashboard_data.metrics,
        'last_updated': dashboard_data.last_updated.isoformat(),
        'user': {
            'username': session.get('username'),
            'role': session.get('role')
        }
    }
    
    # If not admin, limit sensitive information
    if session.get('role') != 'admin':
        # Remove or obfuscate sensitive fields from events
        for event in response_data['events']:
            if 'data' in event and isinstance(event['data'], list):
                # Example: Obscure sensitive data in events for non-admins
                if any(sensitive in str(event).lower() for sensitive in ['password', 'secret', 'key']):
                    event['data'] = ['[REDACTED - Requires Admin Access]']
    
    return jsonify(response_data)

# WebSocket event handlers
@socketio.on('connect')
@authenticated_only
def handle_connect():
    """Handle new WebSocket connections."""
    logger.info(f"Client connected: {session.get('username')}")
    # Send current data to new client
    emit('data_update', {
        'metrics': dashboard_data.metrics,
        'last_updated': dashboard_data.last_updated.isoformat(),
        'user': {
            'username': session.get('username'),
            'role': session.get('role')
        }
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info("Client disconnected")

if __name__ == '__main__':
    # Initial data load
    update_dashboard_data()
    
    # Start background thread
    thread = threading.Thread(target=background_thread, daemon=True)
    thread.start()
    
    # Start the web server
    logger.info("Starting SIEM Dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
