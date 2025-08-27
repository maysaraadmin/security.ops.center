#!/usr/bin/env python3
"""
Start script for the EDR Web Application and Agent.

This script initializes and starts both the web interface and the EDR agent
with proper configuration and error handling.
"""
import os
import sys
import time
import signal
import logging
import threading
import webbrowser
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

# Configure logging before importing other modules
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/startup.log')
    ]
)

logger = logging.getLogger(__name__)

# Import application components
from src.web.app_enhanced import app, socketio
from src.edr.agent.edr_agent import EDRAgent
from src.common.config import Config
from src.web.config import get_web_config

# Global variables
edr_agent = None
web_thread = None
shutdown_event = threading.Event()

def start_edr_agent():
    """Initialize and start the EDR agent."""
    global edr_agent
    
    try:
        # Get configuration
        config = Config()
        
        # Initialize EDR agent
        edr_agent = EDRAgent(config={
            'log_level': config.get('edr.log_level', 'INFO'),
            'log_file': config.get('edr.log_file', 'logs/edr_agent.log'),
            'checkin_interval': config.get('edr.checkin_interval', 300),
            'max_offline_time': config.get('edr.max_offline_time', 900),
        })
        
        logger.info("Starting EDR agent...")
        edr_agent.start()
        logger.info("EDR agent started successfully")
        
        # Keep the agent running until shutdown is requested
        while not shutdown_event.is_set():
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Failed to start EDR agent: {e}", exc_info=True)
        shutdown()


def start_web_interface():
    """Start the Flask web interface."""
    try:
        # Get web configuration
        web_config = get_web_config()
        host = web_config.get('app.host', '0.0.0.0')
        port = web_config.get('app.port', 5000)
        
        logger.info(f"Starting web interface on http://{host}:{port}")
        
        # Start the web server in a separate thread
        socketio.run(
            app,
            host=host,
            port=port,
            debug=web_config.get('app.debug', False),
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}", exc_info=True)
        shutdown()


def open_browser():
    """Open the default web browser to the application."""
    web_config = get_web_config()
    host = web_config.get('app.host', '0.0.0.0')
    port = web_config.get('app.port', 5000)
    
    # Wait for the server to start
    time.sleep(2)
    
    try:
        url = f"http://{host if host != '0.0.0.0' else 'localhost'}:{port}"
        webbrowser.open(url)
        logger.info(f"Opened web browser to {url}")
    except Exception as e:
        logger.warning(f"Could not open web browser: {e}")


def signal_handler(sig, frame):
    """Handle termination signals."""
    logger.info("Shutdown signal received, shutting down...")
    shutdown()


def shutdown():
    """Gracefully shut down the application."""
    global edr_agent, web_thread
    
    logger.info("Shutting down...")
    shutdown_event.set()
    
    # Stop the EDR agent if it's running
    if edr_agent and hasattr(edr_agent, 'stop'):
        try:
            logger.info("Stopping EDR agent...")
            edr_agent.stop()
        except Exception as e:
            logger.error(f"Error stopping EDR agent: {e}", exc_info=True)
    
    # Stop the web server if it's running
    if web_thread and web_thread.is_alive():
        try:
            logger.info("Stopping web server...")
            # This is a simple way to stop the Flask development server
            # In production, you'd want a more robust solution
            os._exit(0)
        except Exception as e:
            logger.error(f"Error stopping web server: {e}", exc_info=True)
    
    logger.info("Shutdown complete")
    sys.exit(0)


def main():
    """Main entry point for the application."""
    # Create necessary directories
    for directory in ['logs', 'data', 'uploads', 'tmp']:
        os.makedirs(directory, exist_ok=True)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start the EDR agent in a separate thread
        edr_thread = threading.Thread(target=start_edr_agent, daemon=True)
        edr_thread.start()
        
        # Start the web interface in the main thread
        # (Flask's reloader doesn't work well in a separate thread)
        if '--no-browser' not in sys.argv:
            # Start browser in a separate thread after a short delay
            threading.Timer(1, open_browser).start()
        
        start_web_interface()
        
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        shutdown()


if __name__ == "__main__":
    main()
