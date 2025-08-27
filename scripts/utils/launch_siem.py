"""
Simple script to launch the SIEM component.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('siem_launcher')

def main():
    """Main function to launch the SIEM component."""
    try:
        logger.info("Starting SIEM component...")
        
        # Import SIEM launcher
        from src.siem.launcher import SIEMLauncher
        
        # Create a minimal configuration with all components disabled by default
        config = {
            'siem': {
                'logging': {
                    'level': 'INFO',
                    'console': {'enabled': True},
                    'file': {
                        'enabled': True,
                        'path': 'logs/siem.log',
                        'max_size': 100,  # MB
                        'backup_count': 5
                    }
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
        
        # Create and initialize the launcher
        launcher = SIEMLauncher(config)
        
        if launcher.initialize():
            logger.info("SIEM initialized successfully. Starting...")
            launcher.start()
            
            # Keep the main thread alive
            try:
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down SIEM...")
                launcher.stop()
                logger.info("SIEM stopped successfully")
        else:
            logger.error("Failed to initialize SIEM")
            return 1
            
    except Exception as e:
        logger.error(f"Error launching SIEM: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
