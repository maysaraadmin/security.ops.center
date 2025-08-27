"""
API Blueprint
------------
REST API endpoints for the EDR web interface.
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

# Create blueprint
bp = Blueprint('api', __name__)

@bp.route('/status')
@login_required
def get_status():
    """Get the current status of the EDR agent."""
    from ...edr.agent.edr_agent import edr_agent
    
    if not edr_agent:
        return jsonify({
            'status': 'not_initialized',
            'message': 'EDR agent is not initialized'
        })
        
    return jsonify({
        'status': 'running' if edr_agent.running else 'stopped',
        'version': '1.0.0',
        'uptime': edr_agent.get_uptime() if edr_agent.running else 0,
        'event_count': len(edr_agent.events) if hasattr(edr_agent, 'events') else 0
    })

@bp.route('/alerts')
@login_required
def get_alerts():
    """Get a list of security alerts."""
    # In a real app, this would fetch alerts from the database
    return jsonify({
        'alerts': [],
        'total': 0
    })

@bp.route('/endpoints')
@login_required
def get_endpoints():
    """Get a list of managed endpoints."""
    # In a real app, this would fetch endpoints from the database
    return jsonify({
        'endpoints': [],
        'total': 0
    })
