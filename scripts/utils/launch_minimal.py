"""
Minimal SIEM Launcher

This script provides a simple way to start the SIEM with minimal configuration.
"""
import sys
import os
import logging
import threading
import time
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_launch.log')
    ]
)
logger = logging.getLogger('siem.launcher')

def main():
    try:
        logger.info("Starting minimal SIEM launcher...")
        
        # Add the project root to the Python path
        project_root = str(Path(__file__).parent.absolute())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Import SIEM core
        from src.siem.core.siem import SIEM
        
        # Create minimal configuration
        config = {
            'logging': {
                'level': 'INFO',
                'file': 'siem.log',
                'max_size': 10,
                'backup_count': 5
            },
            'database': {
                'url': 'sqlite:///data/siem_minimal.db',
                'pool_size': 5,
                'max_overflow': 10,
                'echo': False
            },
            'api': {
                'host': '127.0.0.1',
                'port': 8000,
                'debug': True,
                'secret_key': 'dev-secret-key',
                'cors_origins': ['*']
            },
            'plugins': [],  # No plugins for now
            'plugins_config': {}
        }
        
        # Initialize SIEM
        logger.info("Initializing SIEM...")
        siem = SIEM(config=config)
        
        # Start SIEM in a separate thread
        logger.info("Starting SIEM...")
        siem_thread = threading.Thread(target=siem.start, daemon=True)
        siem_thread.start()
        
        # Wait for SIEM to initialize
        time.sleep(2)
        
        # Check if SIEM is running
        if hasattr(siem, 'running') and siem.running:
            logger.info("SIEM is running!")
            logger.info(f"API should be available at http://{config['api']['host']}:{config['api']['port']}")
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down SIEM...")
                if hasattr(siem, 'stop'):
                    siem.stop()
                logger.info("SIEM has been shut down.")
        else:
            logger.error("Failed to start SIEM. Check the logs for more details.")
            return 1
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
