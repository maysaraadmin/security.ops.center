"""
Simple EDR Service

A minimal implementation of the EDR service that can run without all components.
"""
import os
import sys
import time
import logging
import threading
import random
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('simple_edr.log')
    ]
)
logger = logging.getLogger('simple_edr')

class SimpleEDR:
    """A simple EDR service that can run with minimal components."""
    
    def __init__(self, config=None):
        """Initialize the simple EDR service."""
        self.config = config or {}
        self.running = False
        self.monitored_processes = []
        logger.info("SimpleEDR initialized")
    
    def initialize(self):
        """Initialize the EDR service."""
        logger.info("Initializing SimpleEDR...")
        
        # Simulate some monitored processes
        self.monitored_processes = [
            "explorer.exe",
            "chrome.exe",
            "python.exe",
            "svchost.exe"
        ]
        
        logger.info("SimpleEDR initialized successfully")
        return True
    
    def start(self):
        """Start the EDR service."""
        if self.running:
            logger.warning("EDR is already running")
            return False
        
        logger.info("Starting SimpleEDR...")
        self.running = True
        
        # Start monitoring processes
        def monitor_processes():
            while self.running:
                # Simulate process monitoring
                for proc in self.monitored_processes:
                    if random.random() < 0.1:  # 10% chance of an event
                        logger.info(f"Detected process event: {proc} (PID: {random.randint(1000, 9999)})")
                time.sleep(5)
        
        self.monitor_thread = threading.Thread(target=monitor_processes, daemon=True)
        self.monitor_thread.start()
        
        logger.info("SimpleEDR started successfully")
        return True
    
    def stop(self):
        """Stop the EDR service."""
        if not self.running:
            logger.warning("EDR is not running")
            return False
        
        logger.info("Stopping SimpleEDR...")
        self.running = False
        
        # Wait for monitor thread to finish
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        
        logger.info("SimpleEDR stopped successfully")
        return True

def main():
    """Main entry point for the simple EDR service."""
    import signal
    
    # Create and initialize the EDR
    edr = SimpleEDR()
    
    # Set up signal handlers
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        edr.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize and start the EDR
    if not edr.initialize():
        logger.error("Failed to initialize EDR")
        return 1
    
    if not edr.start():
        logger.error("Failed to start EDR")
        return 1
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    finally:
        edr.stop()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
