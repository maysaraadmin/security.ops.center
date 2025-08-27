"""
Run the SIEM web interface.
This script is a simple wrapper to ensure proper Python path handling.
"""

import os
import sys
import logging
from pathlib import Path

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_web.log')
    ]
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
sys.path.insert(0, project_root)

def load_config():
    """Load SIEM configuration from file."""
    import yaml
    
    # Possible config file locations
    config_paths = [
        os.path.join(os.path.dirname(__file__), 'config', 'siem_config.yaml'),
        os.path.join(os.path.dirname(__file__), '..', 'config', 'siem_config.yaml'),
        os.path.join(os.getcwd(), 'config', 'siem_config.yaml')
    ]
    
    for config_path in config_paths:
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
                logger.info(f"Successfully loaded configuration from {config_path}")
                return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
    
    # If we get here, no config was loaded
    logger.warning("No valid configuration file found, using default configuration")
    return {
        'siem': {
            'host': '0.0.0.0',
            'port': 5000,
            'debug': True
        },
        'logging': {
            'level': 'DEBUG',
            'file': 'siem_web.log'
        }
    }

def main():
    # Set up environment variables first
    os.environ['FLASK_APP'] = 'src.siem.web:create_app()'
    os.environ['FLASK_ENV'] = 'development'
    
    # Import create_app after setting up the path
    from src.siem.web import create_app
    
    try:
        # Load configuration
        config = load_config()
        
        # Create and run the app with config
        logger.info("Starting SIEM web interface...")
        app = create_app(config=config)
        
        # Log available routes
        logger.info("Available routes:")
        for rule in app.url_map.iter_rules():
            logger.info(f"  {rule.endpoint}: {rule.rule} ({', '.join(rule.methods)})")
        
        # Run the app
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
        
    except Exception as e:
        logger.error(f"Failed to start SIEM web interface: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
