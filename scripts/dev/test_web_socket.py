"""
SIEM Web Interface

A Flask application with Socket.IO for real-time SIEM monitoring and control.
"""
import os
import sys
from pathlib import Path
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import time

# Add project root to path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import SIEM manager
from src.web.siem_manager import siem_manager

# Initialize Flask app
app = Flask(__name__, template_folder='web/templates')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize Socket.IO with threading for better compatibility
socketio = SocketIO(
    app,
    async_mode='threading',
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mock user database (replace with a real database in production)
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# Create a default admin user (username: admin, password: admin)
# In production, use a proper user database
users = {
    1: User(1, 'admin', generate_password_hash('admin'))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    """Render the main dashboard."""
    return render_template('dashboard.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user by username (in a real app, query the database)
        user = next((u for u in users.values() if u.username == username), None)
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
            
        return 'Invalid username or password', 401
        
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

# API Endpoints
@app.route('/api/status')
@login_required
def get_status():
    """Get the current status of all components."""
    return jsonify(siem_manager.get_status())

@app.route('/api/components/<component_name>/start', methods=['POST'])
@login_required
def start_component(component_name):
    """Start a specific component."""
    if component_name in siem_manager.components:
        success = siem_manager.components[component_name].start()
        return jsonify({'status': 'started' if success else 'already_running'})
    return jsonify({'error': 'Component not found'}), 404

@app.route('/api/components/<component_name>/stop', methods=['POST'])
@login_required
def stop_component(component_name):
    """Stop a specific component."""
    if component_name in siem_manager.components:
        success = siem_manager.components[component_name].stop()
        return jsonify({'status': 'stopped' if success else 'already_stopped'})
    return jsonify({'error': 'Component not found'}), 404

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection."""
    if not current_user.is_authenticated:
        return False  # Reject the connection if not authenticated
    
    print(f'Client connected: {request.sid}')
    
    # Send the current status immediately
    emit('status_update', siem_manager.get_status())

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    print(f'Client disconnected: {request.sid}')

@socketio.on('start_component')
@login_required
def handle_start_component(data):
    """Handle start component request."""
    component_name = data.get('component')
    if component_name in siem_manager.components:
        siem_manager.components[component_name].start()
        return {'status': 'success'}
    return {'status': 'error', 'message': 'Component not found'}

@socketio.on('stop_component')
@login_required
def handle_stop_component(data):
    """Handle stop component request."""
    component_name = data.get('component')
    if component_name in siem_manager.components:
        siem_manager.components[component_name].stop()
        return {'status': 'success'}
    return {'status': 'error', 'message': 'Component not found'}

def status_callback(status):
    """Callback for status updates from the SIEM manager."""
    socketio.emit('status_update', status)

if __name__ == '__main__':
    # Register status callback
    siem_manager.register_status_callback(status_callback)
    
    # Start status updates
    siem_manager.start_status_updates(interval=1.0)
    
    # Start all components by default
    siem_manager.start_all()
    
    print("Starting SIEM Web Interface...")
    print(" * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)")
    print(" * Login with username: admin, password: admin")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\nStopping SIEM components...")
        siem_manager.stop_all()
        siem_manager.stop_status_updates()
    
    print("Server stopped")
