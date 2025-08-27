"""
EDR Agent Web Interface
----------------------
A web-based interface for monitoring and managing the EDR agent.
"""
import os
import json
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Local imports
from edr.agent.edr_agent import EDRAgent, EDREvent, EventSeverity

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'
    EDR_CONFIG = {
        'log_level': 'INFO',
        'log_file': 'logs/edr_agent.log',
        'max_history': 1000,
        'monitoring_interval': 2.0
    }

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize EDR Agent
edr_agent = EDRAgent(Config.EDR_CONFIG)

# Mock user database (replace with a real database in production)
users = {
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin'),  # Change this in production!
        'role': 'admin'
    }
}

# User class for Flask-Login
class User:
    def __init__(self, username):
        self.username = username
        self.role = users[username]['role']
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return self.username

    @staticmethod
    def get(user_id):
        if user_id not in users:
            return None
        return User(user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username)
            login_user(user)
            return jsonify({'status': 'success', 'redirect': url_for('index')})
        
        return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# API Endpoints
@app.route('/api/status')
@login_required
def get_status():
    return jsonify(edr_agent.get_status())

@app.route('/api/events')
@login_required
def get_events():
    limit = request.args.get('limit', 100, type=int)
    events = [e.to_dict() for e in edr_agent.get_event_history(limit)]
    return jsonify(events)

@app.route('/api/events/<event_id>')
@login_required
def get_event(event_id):
    for event in edr_agent.get_event_history():
        if event.event_id == event_id:
            return jsonify(event.to_dict())
    return jsonify({'error': 'Event not found'}), 404

@app.route('/api/metrics')
@login_required
def get_metrics():
    limit = request.args.get('limit', 60, type=int)
    metrics = [m.to_dict() for m in edr_agent.get_metrics_history(limit)]
    return jsonify(metrics)

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('status', {'data': 'Connected'})
    else:
        return False  # Not authorized

@socketio.on('get_status')
@login_required
def handle_status():
    emit('status_update', edr_agent.get_status())

@socketio.on('get_events')
@login_required
def handle_events(data):
    limit = data.get('limit', 10)
    events = [e.to_dict() for e in edr_agent.get_event_history(limit)]
    emit('events_update', events)

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Start the EDR agent when the app starts
if not edr_agent.running:
    edr_agent.start()

# Register callbacks for real-time updates
@edr_agent.callbacks['event_received']
def on_event_received(event):
    socketio.emit('new_event', event.to_dict())

@edr_agent.callbacks['metrics_updated']
def on_metrics_updated(metrics):
    socketio.emit('metrics_update', metrics.to_dict())

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('static/uploads', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/web_edr.log'),
            logging.StreamHandler()
        ]
    )
    
    # Start the application
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
