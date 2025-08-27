"""
EDR Agent Web Interface
----------------------
A modern web-based interface for the EDR Agent with real-time monitoring and management.
"""
import os
import json
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Local imports
from edr.agent.edr_agent import EDRAgent, EDREvent, EventSeverity

# Configuration
class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Application
    DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'
    EDR_CONFIG = {
        'log_level': 'INFO',
        'log_file': 'logs/edr_agent.log',
        'max_history': 1000,
        'monitoring_interval': 2.0
    }
    
    # Authentication
    LOGIN_DISABLED = os.environ.get('LOGIN_DISABLED', '0') == '1'
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
csrf = CSRFProtect(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=app.debug,
    engineio_logger=app.debug
)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize EDR Agent
edr_agent = EDRAgent(Config.EDR_CONFIG)

# Mock user database (replace with a real database in production)
users = {
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin'),  # Change this in production!
        'role': 'admin',
        'email': 'admin@example.com',
        'full_name': 'Administrator',
        'last_login': None
    }
}

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['username']
        self.username = user_data['username']
        self.role = user_data['role']
        self.email = user_data.get('email', '')
        self.full_name = user_data.get('full_name', '')
        self.last_login = user_data.get('last_login')
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return self.id

    @staticmethod
    def get(user_id):
        if user_id not in users:
            return None
        return User(users[user_id])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Error Handlers
@app.errorhandler(400)
def bad_request_error(error):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Bad request'}), 400
    return render_template('error.html', error=error, code=400), 400

@app.errorhandler(401)
def unauthorized_error(error):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Unauthorized'}), 401
    return redirect(url_for('login', next=request.url))

@app.errorhandler(403)
def forbidden_error(error):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('error.html', error=error, code=403), 403

@app.errorhandler(404)
def not_found_error(error):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Not found'}), 404
    return render_template('error.html', error=error, code=404), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Internal Server Error: {error}')
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('error.html', error=error, code=500), 500

# Routes
@app.route('/')
@login_required
def index():
    return render_template('dashboard_new.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # For development, allow any login if LOGIN_DISABLED is True
        if app.config['LOGIN_DISABLED']:
            user_data = {
                'username': 'dev',
                'role': 'admin',
                'email': 'dev@example.com',
                'full_name': 'Developer',
                'last_login': datetime.utcnow().isoformat()
            }
            user = User(user_data)
            login_user(user)
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'redirect': url_for('index')
                })
            return redirect(url_for('index'))
        
        # Normal authentication flow
        if username in users and check_password_hash(users[username]['password'], password):
            # Update last login time
            users[username]['last_login'] = datetime.utcnow().isoformat()
            
            # Create user object and log in
            user = User(users[username])
            login_user(user)
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'redirect': request.args.get('next') or url_for('index')
                })
                
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        # Failed login
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'status': 'error',
                'message': 'Invalid username or password'
            }), 401
            
        flash('Invalid username or password', 'danger')
    
    # GET request or failed login
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
    return render_template('login_new.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# API Endpoints
@app.route('/api/status')
@login_required
def get_status():
    status = edr_agent.get_status()
    return jsonify(status)

@app.route('/api/events')
@login_required
def get_events():
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('type')
    severity = request.args.get('severity')
    source = request.args.get('source')
    
    events = edr_agent.get_event_history(limit)
    filtered_events = []
    
    for event in events:
        event_dict = event.to_dict()
        
        # Apply filters
        if event_type and event_dict.get('event_type') != event_type:
            continue
            
        if severity and event_dict.get('severity') != severity.upper():
            continue
            
        if source and event_dict.get('source') != source:
            continue
            
        filtered_events.append(event_dict)
    
    return jsonify(filtered_events)

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
@login_required
def handle_connect():
    app.logger.info(f'Client connected: {request.sid}')
    emit('status', {'data': 'Connected'})

@socketio.on('disconnect')
@login_required
def handle_disconnect():
    app.logger.info(f'Client disconnected: {request.sid}')

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

# Register callbacks for real-time updates
@edr_agent.callbacks['event_received']
def on_event_received(event):
    socketio.emit('new_event', event.to_dict())

@edr_agent.callbacks['metrics_updated']
def on_metrics_updated(metrics):
    socketio.emit('metrics_update', metrics.to_dict())

@edr_agent.callbacks['agent_started']
def on_agent_started():
    socketio.emit('agent_status', {'status': 'running'})

@edr_agent.callbacks['agent_stopped']
def on_agent_stopped():
    socketio.emit('agent_status', {'status': 'stopped'})

# Helper function to generate CSRF token for API requests
@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf()}

# Start the EDR agent when the app starts
if not edr_agent.running:
    edr_agent.start()

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
    
    # Log startup information
    app.logger.info('Starting EDR Web Interface...')
    app.logger.info(f'Debug mode: {app.debug}')
    app.logger.info(f'Login disabled: {app.config["LOGIN_DISABLED"]}')
    
    # Start the application
    socketio.run(app, 
                host=os.environ.get('HOST', '127.0.0.1'),  # Changed to 127.0.0.1 for better Windows compatibility
                port=int(os.environ.get('PORT', 5000)),
                debug=app.debug,
                use_reloader=False)
