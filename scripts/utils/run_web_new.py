"""
Run the SIEM Web Interface

This script starts the Flask web interface for the SIEM system.
"""
import os
import sys
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set up environment
os.environ['FLASK_APP'] = 'web.app'
os.environ['FLASK_ENV'] = 'development'

# Import the app
try:
    from src.web.app import app, socketio
except ImportError as e:
    print(f"Error importing web app: {e}")
    print("Please make sure you have installed all required dependencies.")
    print("Run: pip install -r web/requirements.txt")
    sys.exit(1)

def main():
    """Run the web interface."""
    print("Starting SIEM Web Interface...")
    print(f" * Environment: {os.getenv('FLASK_ENV', 'production')}")
    print(f" * Debug mode: {app.debug}")
    print(f" * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)")
    
    # Run the app
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=True)
    except Exception as e:
        print(f"Error starting web interface: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
