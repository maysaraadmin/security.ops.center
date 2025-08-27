"""
Headless SIEM Launcher

A minimal, headless launcher for the SIEM service with all UI components disabled.
"""
import os
import sys
import logging
import signal
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('headless_siem.log')
    ]
)
logger = logging.getLogger('headless_siem')

def signal_handler(sig, frame):
    """Handle shutdown signals."""
    logger.info("Shutdown signal received. Stopping SIEM...")
    if 'siem' in globals():
        siem.stop()
    logger.info("SIEM stopped successfully")
    sys.exit(0)

def main():
    """Main function to launch the SIEM service in headless mode."""
    try:
        logger.info("Starting headless SIEM service...")
        
        # Import SIEM class
        from src.siem.core.siem import SIEM
        
        # Minimal configuration with UI components disabled
        config = {
            'siem': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False,
                'headless': True,  # Explicitly enable headless mode
                'logging': {
                    'level': 'DEBUG',
                    'file': 'logs/headless_siem.log'
                },
                # Disable all components by default
                'log_collector': {'enabled': False},
                'correlation': {'enabled': False},
                'edr': {'enabled': False},
                'ndr': {'enabled': False},
                'dlp': {'enabled': False},
                'fim': {'enabled': False},
                'hips': {'enabled': False},
                'nips': {'enabled': False},
                'compliance': {'enabled': False},
                'monitoring': {'enabled': False},
                'ui': {'enabled': False}  # Explicitly disable UI
            }
        }
        
        # Initialize SIEM
        logger.info("Initializing SIEM...")
        global siem
        siem = SIEM(config)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start SIEM
        logger.info("Starting SIEM...")
        siem.start()
        
        # Keep the service running
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
            siem.stop()
            logger.info("SIEM stopped successfully")
            
    except Exception as e:
        logger.error(f"Error in headless SIEM launcher: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
