"""
Simple SIEM Launcher

A minimal launcher for the SIEM service with direct initialization.
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
        logging.FileHandler('siem_launcher.log')
    ]
)
logger = logging.getLogger('siem_launcher')

def main():
    """Main function to launch the SIEM service."""
    try:
        logger.info("Starting SIEM service...")
        
        # Import SIEM class from the correct module
        from src.siem.core.siem import SIEM
        
        # Minimal configuration
        config = {
            'siem': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': True,
                'logging': {
                    'level': 'DEBUG',
                    'file': 'logs/siem.log'
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
                'monitoring': {'enabled': False}
            }
        }
        
        # Initialize and start SIEM
        logger.info("Initializing SIEM...")
        siem = SIEM(config)
        
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
        logger.error(f"Error in SIEM launcher: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
