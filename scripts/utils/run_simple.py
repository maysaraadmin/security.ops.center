"""
Simple SIEM launcher for headless operation.
"""
import os
import sys
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem.log')
    ]
)
logger = logging.getLogger('siem.simple')

def main():
    try:
        logger.info("Starting SIEM in simple mode...")
        
        # Import core components
        from src.siem.core.siem import SIEM
        from src.siem.config import load_config
        
        # Load configuration
        config = load_config()
        
        # Initialize and start SIEM
        siem = SIEM(config=config, headless=True)
        siem.start()
        
        logger.info("SIEM is running. Press Ctrl+C to stop.")
        
        # Keep running
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down SIEM...")
        siem.stop()
        logger.info("SIEM stopped.")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
