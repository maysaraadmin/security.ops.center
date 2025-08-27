"""
Authentication Blueprint
-----------------------
Handles user authentication, login, logout, and session management.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

# Create blueprint
bp = Blueprint('auth', __name__)

# Mock user database - replace with actual database in production
USERS = {
    'admin': {
        'password': 'pbkdf2:sha256:260000$YOUR_PASSWORD_HASH',
        'role': 'admin',
        'email': 'admin@example.com',
        'full_name': 'Admin User'
    }
}

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = USERS.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            from ..models.user import User
            user = User({
                'username': username,
                'role': user_data['role'],
                'email': user_data['email'],
                'full_name': user_data['full_name']
            })
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
            
        flash('Invalid username or password', 'error')
        
    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('auth.login'))
