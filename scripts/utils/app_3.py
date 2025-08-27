"""
SIEM Web Interface

A Flask-based web interface for the SIEM system.
"""
import os
import logging
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from pathlib import Path
import sys

# Add project root to path
project_root = str(Path(__file__).parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web.log')
    ]
)
logger = logging.getLogger('siem.web')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'dev-secret-key')
socketio = SocketIO(app, async_mode='eventlet')

# Mock SIEM status for development
siem_status = {
    'status': 'stopped',
    'components': {
        'log_collector': {'status': 'stopped', 'enabled': True},
        'correlation_engine': {'status': 'stopped', 'enabled': True},
        'dummy_component': {'status': 'stopped', 'enabled': True},
    },
    'stats': {
        'events_processed': 0,
        'alerts_triggered': 0,
        'uptime': 0
    }
}

@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html', status=siem_status)

@app.route('/api/status')
def get_status():
    """Get current SIEM status."""
    return jsonify(siem_status)

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connections."""
    logger.info('Client connected')
    socketio.emit('status_update', siem_status)

@socketio.on('start_component')
def handle_start_component(data):
    """Handle start component request."""
    component = data.get('component')
    if component in siem_status['components']:
        logger.info(f'Starting component: {component}')
        siem_status['components'][component]['status'] = 'starting'
        socketio.emit('status_update', siem_status)
        
        # In a real implementation, this would start the actual component
        # For now, we'll just simulate it
        socketio.start_background_task(
            simulate_component_start,
            component,
            socketio
        )
        return {'status': 'success'}
    return {'status': 'error', 'message': 'Invalid component'}

def simulate_component_start(component, socketio):
    """Simulate component starting up."""
    import time
    time.sleep(1)  # Simulate startup time
    siem_status['components'][component]['status'] = 'running'
    socketio.emit('status_update', siem_status)

if __name__ == '__main__':
    logger.info('Starting SIEM Web Interface...')
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
