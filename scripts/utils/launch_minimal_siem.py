"""
Minimal SIEM Launcher

A simple launcher for the SIEM service with minimal configuration.
"""
import os
import sys
import logging
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
        logging.FileHandler('minimal_siem_launcher.log')
    ]
)
logger = logging.getLogger('minimal_siem_launcher')

def main():
    """Main function to launch the SIEM service with minimal configuration."""
    try:
        logger.info("Starting minimal SIEM service...")
        
        # Import SIEM class
        from src.siem.core.siem import SIEM
        
        # Use the minimal configuration
        config_path = os.path.join('config', 'minimal_siem.yaml')
        logger.info(f"Loading configuration from {config_path}")
        
        # Initialize and start SIEM with the config file
        siem = SIEM(config_path)
        
        logger.info("Initializing SIEM...")
        siem.initialize()
        
        logger.info("Starting SIEM...")
        siem.start()
        
        # Keep the service running
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down SIEM...")
            siem.stop()
            logger.info("SIEM stopped successfully")
            
    except Exception as e:
        logger.error(f"Error in minimal SIEM launcher: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
