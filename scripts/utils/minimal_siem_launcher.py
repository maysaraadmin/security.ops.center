# minimal_siem_launcher.py
import sys
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
        logging.FileHandler('minimal_siem.log')
    ]
)
logger = logging.getLogger('siem.minimal')

def main():
    try:
        logger.info("Starting minimal SIEM...")
        
        # Add the project root to the Python path
        project_root = str(Path(__file__).parent.absolute())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Import core components
        from src.siem.core.siem import SIEM
        
        # Create minimal configuration
        config = {
            'logging': {
                'level': 'INFO',
                'file': 'siem_minimal.log'
            },
            'database': {
                'url': 'sqlite:///data/siem_minimal.db',
                'pool_size': 5
            },
            'api': {
                'host': '127.0.0.1',
                'port': 8080,
                'debug': True
            },
            'plugins': [],  # No plugins for now
            'plugins_config': {}
        }
        
        # Initialize and start SIEM
        logger.info("Initializing SIEM with minimal configuration...")
        
        try:
            # Initialize SIEM
            siem = SIEM(config=config)
            logger.info("SIEM instance created successfully")
            
            # Try to access the start method
            if not hasattr(siem, 'start'):
                raise AttributeError("SIEM instance has no 'start' method")
                
            # Start the SIEM in a separate thread
            logger.info("Starting SIEM in a separate thread...")
            siem_thread = threading.Thread(target=siem.start, daemon=True)
            siem_thread.start()
            
            # Wait for SIEM to initialize
            logger.info("Waiting for SIEM to initialize...")
            time.sleep(3)
            
            # Check if SIEM is running
            if hasattr(siem, 'running') and siem.running:
                logger.info("SIEM is running")
            else:
                logger.warning("SIEM running status unknown - continuing anyway")
                
        except Exception as e:
            logger.error(f"Failed to initialize SIEM: {e}", exc_info=True)
            raise
        
        logger.info("SIEM is running in minimal mode. Press Ctrl+C to stop.")
        logger.info(f"API should be available at http://{config['api']['host']}:{config['api']['port']}")
        
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
        logger.error(f"Fatal error: {e}", exc_info=True)
        logger.error("SIEM failed to start. Check the logs for more details.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
