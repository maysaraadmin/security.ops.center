"""
Dummy SIEM Launcher

A simple launcher that starts the SIEM with just the dummy component for testing.
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
        logging.FileHandler('dummy_siem.log')
    ]
)
logger = logging.getLogger('dummy_launcher')

def main():
    try:
        logger.info("Starting dummy SIEM launcher...")
        
        # Add the project root to the Python path
        project_root = str(Path(__file__).parent.absolute())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Import SIEM core
        from src.siem.core.simple_siem import SimpleSIEM
        
        # Create minimal configuration
        config = {
            'logging': {
                'level': 'INFO',
                'console': {
                    'enabled': True,
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'file': {
                    'enabled': True,
                    'level': 'DEBUG',
                    'path': 'dummy_siem.log',
                    'max_size': 10,  # MB
                    'backup_count': 5,
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            },
            'components': {
                'enabled': ['dummy_component'],
                'dummy_component': {
                    'interval': 2  # Log every 2 seconds
                }
            }
        }
        
        # Initialize and start SIEM
        logger.info("Initializing SimpleSIEM with dummy component...")
        siem = SimpleSIEM(config=config)
        
        # Start SIEM
        logger.info("Starting SimpleSIEM...")
        siem.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down SimpleSIEM...")
            siem.stop()
            logger.info("SimpleSIEM has been shut down.")
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
