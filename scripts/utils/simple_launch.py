"""
Simple SIEM Launcher

A minimal launcher for the SIEM system that works with the current codebase.
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
        logger.info("Starting simple SIEM launcher...")
        
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
                'file': 'siem.log',
                'max_size': 10,  # MB
                'backup_count': 5
            },
            'components': {
                'enabled': ['dummy_component']
            }
        }
        
        # Initialize and start SIEM
        logger.info("Initializing SimpleSIEM...")
        siem = SimpleSIEM(config=config)
        
        # Start SIEM in a separate thread
        logger.info("Starting SimpleSIEM...")
        siem_thread = threading.Thread(target=siem.start, daemon=True)
        siem_thread.start()
        
        # Wait for SIEM to initialize
        time.sleep(2)
        
        if hasattr(siem, 'running') and siem.running:
            logger.info("SimpleSIEM is running!")
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down SimpleSIEM...")
                siem.stop()
                logger.info("SimpleSIEM has been shut down.")
        else:
            logger.error("Failed to start SimpleSIEM. Check the logs for more details.")
            return 1
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
