"""
Minimal SIEM launcher for testing.
"""

import os
import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('minimal_launcher')

def main():
    """Run the minimal SIEM launcher."""
    try:
        # Add the project root to the Python path
        project_root = str(Path(__file__).parent.absolute())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        logger.info("Creating minimal configuration...")
        
        # Minimal configuration with all components disabled
        config = {
            'siem': {
                'logging': {
                    'level': 'DEBUG',
                    'console': {'enabled': True},
                    'file': {
                        'enabled': False
                    }
                },
                # Disable all components
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
        
        logger.info("Importing SIEM class...")
        from src.siem.core.siem import SIEM
        
        logger.info("Creating SIEM instance...")
        siem = SIEM(config)
        
        logger.info("Starting SIEM...")
        siem.start()
        
        logger.info("SIEM started successfully. Press Ctrl+C to stop.")
        
        # Keep the script running
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("\nShutting down SIEM...")
        if 'siem' in locals():
            siem.stop()
        logger.info("SIEM stopped")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
