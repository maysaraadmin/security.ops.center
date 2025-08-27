"""
Minimal SIEM implementation for testing basic functionality.
"""

import os
import sys
import logging
import threading
import time
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('minimal_siem')

class MinimalSIEM:
    """Minimal SIEM implementation for testing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the minimal SIEM."""
        self.config = config or {}
        self.running = False
        self.thread = None
        
        # Setup logging
        log_config = self.config.get('logging', {})
        log_level = log_config.get('level', 'INFO').upper()
        logging.getLogger().setLevel(log_level)
        
        logger.info("MinimalSIEM initialized")
    
    def start(self):
        """Start the SIEM."""
        if self.running:
            logger.warning("SIEM is already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("MinimalSIEM started")
    
    def stop(self):
        """Stop the SIEM."""
        if not self.running:
            return
            
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("MinimalSIEM stopped")
    
    def _run(self):
        """Main SIEM loop."""
        logger.info("SIEM main loop started")
        
        try:
            while self.running:
                logger.info("SIEM is running...")
                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in SIEM main loop: {e}", exc_info=True)
        finally:
            logger.info("SIEM main loop stopped")

def main():
    """Main function to run the minimal SIEM."""
    # Minimal configuration
    config = {
        'logging': {
            'level': 'DEBUG',  # Set to DEBUG for more verbose output
            'file': 'logs/minimal_siem.log'
        },
        'components': {
            'log_collector': {'enabled': False},  # Disable log collector for now
            'correlation_engine': {'enabled': False},
            'compliance': {'enabled': False}
        }
    }
    
    # Create and start the SIEM
    siem = MinimalSIEM(config)
    
    try:
        siem.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down SIEM...")
    finally:
        siem.stop()

if __name__ == "__main__":
    main()
