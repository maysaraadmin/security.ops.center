"""
EDR and SIEM Services Launcher (Fixed)

A robust launcher for running both EDR and SIEM services with proper configuration.
"""
import os
import sys
import time
import signal
import logging
import threading
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('edr_siem_launcher.log')
    ]
)
logger = logging.getLogger('edr_siem_launcher')

def run_edr_service():
    """Run the EDR service in the main thread."""
    try:
        # Import here to avoid circular imports
        from src.edr.server import EDRAgentServer
        from src.core.config import load_config
        
        logger.info("Loading EDR configuration...")
        config = load_config('config/edr_config.yaml')
        
        logger.info("Initializing EDR server...")
        edr_server = EDRAgentServer(config.get('edr', {}))
        
        logger.info("Starting EDR server...")
        edr_server.start()
        
        # Keep the thread alive
        while True:
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"EDR service error: {e}", exc_info=True)
        return False

def run_siem_service():
    """Run the SIEM service in a separate thread."""
    try:
        # Import here to avoid circular imports
        from src.siem.core import SIEMCore
        from src.core.config import load_config
        
        logger.info("Loading SIEM configuration...")
        config = load_config('config/siem_config.yaml')
        
        logger.info("Initializing SIEM core...")
        siem = SIEMCore(config)
        
        logger.info("Starting SIEM core...")
        siem.start()
        
        # Keep the thread alive
        while True:
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"SIEM service error: {e}", exc_info=True)
        return False

def main():
    """Main entry point."""
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping services...")
        os._exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting EDR and SIEM services...")
    
    try:
        # Start SIEM in a separate thread
        siem_thread = threading.Thread(target=run_siem_service, daemon=True)
        siem_thread.start()
        
        # Run EDR in the main thread
        run_edr_service()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    # Add the project root to the Python path
    project_root = str(Path(__file__).parent.absolute())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Ensure the config directory exists
    config_dir = os.path.join(project_root, 'config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir, exist_ok=True)
    
    # Set working directory to project root
    os.chdir(project_root)
    
    sys.exit(main())
