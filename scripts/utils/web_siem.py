"""
Web-Enabled SIEM Service

A simple SIEM service with a basic web interface.
"""
import os
import sys
import time
import logging
import threading
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_siem.log')
    ]
)
logger = logging.getLogger('web_siem')

# Initialize Flask app
app = Flask(__name__)

class WebSIEM:
    """A simple SIEM service with a web interface."""
    
    def __init__(self, host='0.0.0.0', port=5000):
        """Initialize the web-enabled SIEM service."""
        self.host = host
        self.port = port
        self.running = False
        self.events = []
        self.stats = {
            'events_processed': 0,
            'alerts_triggered': 0,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'stopped'
        }
        
        # Configure Flask routes
        self._setup_routes()
        
        logger.info("WebSIEM initialized")
    
    def _setup_routes(self):
        """Set up Flask routes."""
        @app.route('/')
        def dashboard():
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>SIEM Dashboard</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        .container { max-width: 1200px; margin: 0 auto; }
                        .header { margin-bottom: 20px; }
                        .stats { display: flex; margin-bottom: 20px; }
                        .stat-box { 
                            border: 1px solid #ddd; 
                            padding: 15px; 
                            margin-right: 10px; 
                            border-radius: 5px;
                            min-width: 200px;
                        }
                        .events { margin-top: 20px; }
                        table { width: 100%; border-collapse: collapse; }
                        th, td { 
                            border: 1px solid #ddd; 
                            padding: 8px; 
                            text-align: left; 
                        }
                        th { background-color: #f2f2f2; }
                        tr:nth-child(even) { background-color: #f9f9f9; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>SIEM Dashboard</h1>
                            <p>Status: <span id="status">{{ status }}</span></p>
                            <p>Uptime: <span id="uptime">{{ uptime }}</span></p>
                        </div>
                        
                        <div class="stats">
                            <div class="stat-box">
                                <h3>Events Processed</h3>
                                <p id="events-count">{{ stats.events_processed }}</p>
                            </div>
                            <div class="stat-box">
                                <h3>Alerts Triggered</h3>
                                <p id="alerts-count">{{ stats.alerts_triggered }}</p>
                            </div>
                            <div class="stat-box">
                                <h3>Start Time</h3>
                                <p>{{ stats.start_time }}</p>
                            </div>
                        </div>
                        
                        <div class="events">
                            <h2>Recent Events</h2>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Source</th>
                                        <th>Event Type</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody id="events-table">
                                    {% for event in events %}
                                    <tr>
                                        <td>{{ event.timestamp }}</td>
                                        <td>{{ event.source }}</td>
                                        <td>{{ event.event_type }}</td>
                                        <td>{{ event.details }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <script>
                        // Auto-refresh the page every 5 seconds
                        setTimeout(function() {
                            window.location.reload();
                        }, 5000);
                    </script>
                </body>
                </html>
            ''', 
            status=self.stats['status'],
            uptime=self._get_uptime(),
            stats=self.stats,
            events=self.events[-20:]  # Show only the last 20 events
        )
        
        @app.route('/api/events')
        def get_events():
            return jsonify({
                'status': 'success',
                'data': self.events[-50:],  # Return last 50 events
                'stats': self.stats
            })
    
    def _get_uptime(self):
        """Calculate uptime in a human-readable format."""
        if not hasattr(self, 'start_time'):
            return '0s'
        
        uptime = datetime.now() - datetime.strptime(self.stats['start_time'], '%Y-%m-%d %H:%M:%S')
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"
    
    def add_event(self, event_type, source, details):
        """Add a new event to the SIEM."""
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': event_type,
            'source': source,
            'details': details
        }
        self.events.append(event)
        self.stats['events_processed'] += 1
        
        # Simple alerting - just an example
        if 'error' in event_type.lower() or 'alert' in event_type.lower():
            self.stats['alerts_triggered'] += 1
            logger.warning(f"ALERT: {event_type} - {details}")
        
        return event
    
    def start(self):
        """Start the SIEM service and web server."""
        if self.running:
            logger.warning("SIEM is already running")
            return False
        
        logger.info("Starting WebSIEM...")
        self.running = True
        self.stats['status'] = 'running'
        
        # Start the web server in a separate thread
        def run_web_server():
            try:
                app.run(host=self.host, port=self.port, debug=False, use_reloader=False)
            except Exception as e:
                logger.error(f"Web server error: {e}")
                self.running = False
        
        self.web_thread = threading.Thread(target=run_web_server, daemon=True)
        self.web_thread.start()
        
        # Start a background thread to simulate events
        def simulate_events():
            import random
            event_sources = ['firewall', 'ids', 'edr', 'system', 'network']
            event_types = ['login', 'logout', 'error', 'alert', 'info', 'warning']
            
            while self.running:
                # Simulate random events
                if random.random() < 0.3:  # 30% chance of an event
                    source = random.choice(event_sources)
                    event_type = random.choice(event_types)
                    details = f"Sample {event_type} event from {source}"
                    self.add_event(event_type, source, details)
                
                time.sleep(2)  # Check for new events every 2 seconds
        
        self.event_thread = threading.Thread(target=simulate_events, daemon=True)
        self.event_thread.start()
        
        logger.info(f"WebSIEM started successfully on http://{self.host}:{self.port}")
        return True
    
    def stop(self):
        """Stop the SIEM service."""
        if not self.running:
            logger.warning("SIEM is not running")
            return False
        
        logger.info("Stopping WebSIEM...")
        self.running = False
        self.stats['status'] = 'stopped'
        
        # Wait for threads to finish
        if hasattr(self, 'web_thread'):
            self.web_thread.join(timeout=5)
        
        if hasattr(self, 'event_thread'):
            self.event_thread.join(timeout=5)
        
        logger.info("WebSIEM stopped successfully")
        return True

def main():
    """Main entry point for the web-enabled SIEM service."""
    import signal
    
    # Create and initialize the SIEM
    siem = WebSIEM(host='0.0.0.0', port=5000)
    
    # Set up signal handlers
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        siem.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the SIEM
    if not siem.start():
        logger.error("Failed to start SIEM")
        return 1
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    finally:
        siem.stop()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
