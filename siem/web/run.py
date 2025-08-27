"""
SIEM Web Interface Launcher

This script starts the SIEM web interface.
"""

import os
import sys
import logging
from pathlib import Path
import yaml

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def load_config():
    """Load SIEM configuration from file."""
    # Look for config in the project root's config directory
    config_path = os.path.join(os.path.dirname(project_root), 'config', 'siem_config.yaml')
    
    # If not found, try the src/config directory (for backward compatibility)
    if not os.path.exists(config_path):
        alt_path = os.path.join(project_root, 'config', 'siem_config.yaml')
        if os.path.exists(alt_path):
            config_path = alt_path
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        raise

def main():
    """Main function to start the SIEM web interface."""
    try:
        # Load configuration
        config = load_config()
        
        # Import and create the Flask app
        from . import create_app
        
        # Create the application
        app = create_app(config)
        
        # Get server configuration
        host = config.get('siem', {}).get('host', '0.0.0.0')
        port = config.get('siem', {}).get('port', 5000)
        debug = config.get('siem', {}).get('debug', False)
        
        print(f"Starting SIEM web interface on http://{host}:{port}")
        app.run(host=host, port=port, debug=debug)
        
    except Exception as e:
        print(f"Failed to start SIEM web interface: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
