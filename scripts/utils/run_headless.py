""
Minimal SIEM Headless Launcher

This script launches the SIEM in headless mode without any UI components.
"""
import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem.log')
    ]
)
logger = logging.getLogger('siem.headless')

def main():
    """Main entry point for the headless SIEM launcher."""
    try:
        logger.info("Starting SIEM in headless mode...")
        
        # Import core components
        from src.siem.core.siem import SIEM
        from src.siem.config import load_config
        
        # Load configuration
        config = load_config("config/siem.yaml")
        
        # Initialize and start SIEM
        siem = SIEM(config=config, headless=True)
        siem.start()
        
        logger.info("SIEM is running in headless mode. Press Ctrl+C to stop.")
        
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
