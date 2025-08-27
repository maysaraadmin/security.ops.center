"""
SIEM Launcher

This script launches the SIEM with the correct configuration.
"""

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

logger = logging.getLogger('siem.launcher')

def main():
    """Main entry point for the SIEM launcher."""
    try:
        logger.info("Starting SIEM...")
        
        # Import core components
        from src.siem.core.siem import SIEM
        from src.siem.config import load_config
        
        # Load configuration
        config_path = Path("config/siem_local.yaml")  # Use local development config
        if not config_path.exists():
            logger.warning(f"Local config not found at {config_path}, falling back to default")
            config_path = Path("config/siem.yaml")
            
        logger.info(f"Loading configuration from {config_path}")
        config = load_config(str(config_path))
        
        # Initialize and start SIEM
        logger.info("Initializing SIEM...")
        siem = SIEM(config=config, headless=True)
        
        # Get API host and port from config
        api_host = config.get('api', {}).get('host', '0.0.0.0')
        api_port = config.get('api', {}).get('port', 8000)
        
        logger.info(f"Starting SIEM API on http://{api_host}:{api_port}")
        siem.start()
        
        logger.info("SIEM is running. Press Ctrl+C to stop.")
        
        # Keep running
        try:
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
