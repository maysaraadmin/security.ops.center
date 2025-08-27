"""
Dummy component for SimpleSIEM.
"""
import logging
import time
import threading
import traceback
from typing import Dict, Any, Optional, Union

# Set up logger with more detailed format
logger = logging.getLogger('siem.components.dummy')

class DummyComponent:
    """A dummy component that logs a message periodically."""
    
    def __init__(self, config: Optional[Union[Dict[str, Any], str]] = None):
        """Initialize the dummy component.
        
        Args:
            config: Configuration dictionary or path to config file
        """
        self.logger = logging.getLogger('siem.components.dummy')
        self.logger.info("Initializing DummyComponent...")
        
        # Handle different config types
        if isinstance(config, str):
            self.logger.info(f"Loading config from file: {config}")
            # In a real implementation, you would load from file here
            self.config = {}
        else:
            self.config = config or {}
        
        self.running = False
        self.thread = None
        self.interval = int(self.config.get('interval', 2))  # Default 2 seconds
        self.enabled = self.config.get('enabled', True)
        
        self.logger.info(f"DummyComponent initialized with config: {self.config}")
        self.logger.info(f"Component will log every {self.interval} seconds")
    
    def get(self, key: str, default=None):
        """Get a configuration value."""
        try:
            value = self.config.get(key, default)
            self.logger.debug(f"Getting config key '{key}': {value}")
            return value
        except Exception as e:
            self.logger.error(f"Error getting config key '{key}': {e}")
            return default
    
    def start(self) -> None:
        """Start the dummy component."""
        self.logger.info("Starting DummyComponent...")
        
        if self.running:
            self.logger.warning("Dummy component is already running")
            return False
            
        if not self.enabled:
            self.logger.info("Dummy component is disabled in configuration")
            return False
        
        try:
            self.running = True
            self.thread = threading.Thread(
                target=self._run, 
                name="DummyComponent-Thread",
                daemon=True
            )
            self.thread.start()
            self.logger.info("Dummy component started successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start DummyComponent: {e}")
            self.logger.debug(traceback.format_exc())
            return False
    
    def stop(self) -> None:
        """Stop the dummy component."""
        self.logger.info("Stopping DummyComponent...")
        
        if not self.running:
            self.logger.info("Dummy component is not running")
            return
            
        self.running = False
        
        if self.thread and self.thread.is_alive():
            self.logger.debug("Waiting for DummyComponent thread to finish...")
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self.logger.warning("DummyComponent thread did not stop gracefully")
            else:
                self.logger.debug("DummyComponent thread stopped")
        
        self.logger.info("Dummy component stopped")
    
    def _run(self) -> None:
        """Main loop for the dummy component."""
        self.logger.info("Dummy component main loop started")
        iteration = 0
        
        while self.running:
            try:
                iteration += 1
                self.logger.info(f"Dummy component iteration {iteration} - Running...")
                self.logger.debug(f"Thread {threading.current_thread().name} is alive")
                
                # Sleep for the interval, but check running flag periodically
                for _ in range(self.interval * 10):  # Check every 100ms
                    if not self.running:
                        break
                    time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Unexpected error in DummyComponent: {e}")
                self.logger.debug(traceback.format_exc())
                time.sleep(5)  # Prevent tight loop on errors
        
        self.logger.info("Dummy component main loop exiting")

# Factory function for the component
def create_component(config: Optional[Union[Dict[str, Any], str]] = None) -> DummyComponent:
    """Create and return a DummyComponent instance."""
    logger = logging.getLogger('siem.components.dummy.factory')
    logger.info("Creating new DummyComponent instance")
    try:
        return DummyComponent(config)
    except Exception as e:
        logger.error(f"Failed to create DummyComponent: {e}")
        logger.debug(traceback.format_exc())
        raise
