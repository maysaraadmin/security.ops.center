"""
Authentication module for the SIEM Dashboard.
"""
import os
import hashlib
import hmac
from functools import wraps
from flask import request, redirect, url_for, session, flash

# In-memory user store (replace with a proper database in production)
USERS = {
    'admin': {
        'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password' hashed
        'role': 'admin'
    },
    'analyst': {
        'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password' hashed
        'role': 'analyst'
    }
}

def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    return hmac.compare_digest(stored_password, hash_password(provided_password))

def login_required(f):
    """Decorator to ensure the user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    """Decorator to ensure the user has the required role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
                
            user_role = USERS.get(session['username'], {}).get('role')
            if user_role != role and user_role != 'admin':
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = USERS.get(username)
        if user and verify_password(user['password'], password):
            session.permanent = True
            session['username'] = username
            session['role'] = user['role']
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        flash('Invalid username or password', 'danger')
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard - Login</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md w-96">
            <h1 class="text-2xl font-bold text-center mb-6">SIEM Dashboard Login</h1>
            
            <div id="flash-messages">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="mb-4 p-3 rounded {% if category == 'success' %}bg-green-100 text-green-700{% else %}bg-red-100 text-red-700{% endif %}">
                                {{ message }}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
            </div>
            
            <form method="POST" action="/login">
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2" for="username">
                        Username
                    </label>
                    <input class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" 
                           id="username" name="username" type="text" placeholder="Username" required>
                </div>
                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-bold mb-2" for="password">
                        Password
                    </label>
                    <input class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline" 
                           id="password" name="password" type="password" placeholder="****************" required>
                </div>
                <div class="flex items-center justify-between">
                    <button class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" 
                            type="submit">
                        Sign In
                    </button>
                </div>
            </form>
            <p class="text-center text-gray-500 text-xs mt-4">
                Default credentials: admin/password or analyst/password
            </p>
        </div>
    </body>
    </html>
    """

def logout():
    """Handle user logout."""
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect('/login')

def init_auth(app):
    """Initialize authentication with the Flask app."""
    # Set a secret key for session management
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-this-in-production')
    
    # Session configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime
    
    return app
