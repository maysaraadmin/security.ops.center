"""
Dashboard Blueprint
------------------
Main dashboard views and functionality for the EDR web interface.
"""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user

# Create blueprint
bp = Blueprint('dashboard', __name__)

@bp.route('/')
@login_required
def index():
    """Render the main dashboard."""
    return render_template('dashboard/index.html', 
                         username=current_user.username,
                         role=current_user.role)

@bp.route('/alerts')
@login_required
def alerts():
    """Render the alerts dashboard."""
    # In a real app, this would fetch alerts from the database
    alerts = []
    return render_template('dashboard/alerts.html', alerts=alerts)

@bp.route('/endpoints')
@login_required
def endpoints():
    """Render the endpoints management view."""
    # In a real app, this would fetch endpoints from the database
    endpoints = []
    return render_template('dashboard/endpoints.html', endpoints=endpoints)
