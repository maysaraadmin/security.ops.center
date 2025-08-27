"""
SIEM Web Application

This module initializes the Flask application and configures it with the
necessary extensions and blueprints.
"""

import os
import logging
from pathlib import Path
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

# Create the Flask application
app = None

# Global SIEM instance
siem = None

def create_app(config=None):
    """
    Application factory function to create and configure the Flask app.
    
    Args:
        config (dict, optional): Configuration dictionary. Defaults to None.
    
    Returns:
        Flask: The configured Flask application instance.
    """
    global app, siem
    
    # Get the root directory of the project
    root_dir = Path(__file__).parent.parent.parent.parent
    
    # Create the Flask app with the correct template and static folders
    template_dir = os.path.join(root_dir, 'src', 'siem', 'web', 'templates')
    static_dir = os.path.join(root_dir, 'src', 'siem', 'web', 'static')
    
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )
    
    # Enable CORS
    CORS(app)
    
    # Basic configuration
    app.config.update(
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'dev-key-change-in-production'),
        JSON_SORT_KEYS=False,
        TEMPLATES_AUTO_RELOAD=True,
        EXPLAIN_TEMPLATE_LOADING=True
    )
    
    # Update with any provided config
    if config:
        app.config.update(config)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(root_dir, 'siem_web.log'))
        ]
    )
    
    # Initialize SIEM instance
    try:
        from ..core.siem import SIEM
        siem = SIEM(config=config)
    except Exception as e:
        logging.error(f"Failed to initialize SIEM: {e}", exc_info=True)
        siem = None
    
    # Import and register blueprints
    from . import routes
    app.register_blueprint(routes.bp, url_prefix='/')
    
    # Add a route to serve static files
    @app.route('/static/<path:filename>')
    def serve_static(filename):
        return send_from_directory(static_dir, filename)
    
    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            'status': 'error',
            'message': 'Resource not found',
            'error': str(error)
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(error)
        }), 500
    
    # Log the configuration
    logging.info(f"Flask app configured with template folder: {template_dir}")
    logging.info(f"Flask app configured with static folder: {static_dir}")
    
    return app

# For development
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
