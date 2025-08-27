"""
EDR and SIEM Services Launcher

A simple launcher for running both EDR and SIEM services with proper configuration.
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
        logging.FileHandler('edr_siem.log')
    ]
)
logger = logging.getLogger('edr_siem_launcher')

def run_edr():
    """Run the EDR service."""
    try:
        from src.edr.launcher import run_edr
        logger.info("Starting EDR service...")
        return run_edr()
    except Exception as e:
        logger.error(f"Failed to start EDR service: {e}", exc_info=True)
        return False

def run_siem():
    """Run the SIEM service."""
    try:
        from src.siem.launcher import run_siem
        logger.info("Starting SIEM service...")
        return run_siem()
    except Exception as e:
        logger.error(f"Failed to start SIEM service: {e}", exc_info=True)
        return False

def main():
    """Main entry point."""
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down services...")
        os._exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting EDR and SIEM services...")
    
    # Start EDR in a separate thread
    edr_thread = threading.Thread(target=run_edr, daemon=True)
    edr_thread.start()
    
    # Start SIEM in the main thread
    siem_success = run_siem()
    
    # If SIEM exits, we'll exit the whole application
    logger.error("SIEM service has stopped. Shutting down...")
    os._exit(1 if not siem_success else 0)

if __name__ == "__main__":
    main()
