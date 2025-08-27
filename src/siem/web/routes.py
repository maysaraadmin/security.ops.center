"""
SIEM Web Interface Routes

This module defines the web routes for the SIEM GUI.
"""

from flask import Blueprint, render_template, jsonify, current_app
import time
from datetime import datetime, timedelta
import psutil
import os

# Create a Blueprint for the web interface
bp = Blueprint('siem_web', __name__, template_folder='templates')

# Store the SIEM start time for uptime calculation
siem_start_time = time.time()

@bp.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@bp.route('/api/status')
def get_status():
    """Get the current status of the SIEM system."""
    try:
        # Get process information
        process = psutil.Process(os.getpid())
        
        # Calculate uptime
        uptime_seconds = time.time() - siem_start_time
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))
        
        # Get memory usage
        memory_info = process.memory_info()
        memory_usage = {
            'rss_mb': memory_info.rss / (1024 * 1024),  # in MB
            'vms_mb': memory_info.vms / (1024 * 1024),  # in MB
        }
        
        # Get CPU usage
        cpu_percent = process.cpu_percent(interval=0.1)
        
        # Prepare status response
        status = {
            'status': 'running',  # or 'stopped' if you implement a stopped state
            'version': '1.0.0',
            'uptime': uptime_str,
            'start_time': datetime.fromtimestamp(siem_start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'memory': memory_usage,
            'cpu_percent': cpu_percent,
            'components': {
                'web_server': {
                    'status': 'running',
                    'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'details': 'Web server is running normally'
                },
                'monitoring': {
                    'status': 'running',
                    'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'details': 'Monitoring service is active'
                },
                'alerting': {
                    'status': 'idle',
                    'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'details': 'No active alerts'
                }
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': status
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting status: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to get status: {str(e)}'
        }), 500

@bp.route('/api/start', methods=['POST'])
def start_siem():
    """Start the SIEM system."""
    try:
        # In a real implementation, you would start your SIEM services here
        # For now, we'll just log and return success
        current_app.logger.info("SIEM start requested")
        
        return jsonify({
            'status': 'success',
            'message': 'SIEM started successfully',
            'data': {
                'status': 'running',
                'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error starting SIEM: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to start SIEM: {str(e)}'
        }), 500

@bp.route('/api/stop', methods=['POST'])
def stop_siem():
    """Stop the SIEM system."""
    try:
        # In a real implementation, you would stop your SIEM services here
        # For now, we'll just log and return success
        current_app.logger.info("SIEM stop requested")
        
        return jsonify({
            'status': 'success',
            'message': 'SIEM stopped successfully',
            'data': {
                'status': 'stopped',
                'stopped_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error stopping SIEM: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to stop SIEM: {str(e)}'
        }), 500
