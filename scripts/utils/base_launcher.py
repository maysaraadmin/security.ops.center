"""
Base Launcher for all SOC components.

This module provides a base class for all SOC component launchers.
"""

import logging
import signal
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseLauncher(ABC):
    """Base class for all SOC component launchers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the base launcher.
        
        Args:
            config: Configuration dictionary for the component.
        """
        self.config = config or {}
        self.logger = logging.getLogger(f'soc.{self.__class__.__name__.lower()}')
        self._running = False
        self._shutdown_event = None
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the component.
        
        Returns:
            bool: True if initialization was successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def start(self) -> None:
        """Start the component."""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the component."""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the component.
        
        Returns:
            Dict containing status information.
        """
        pass
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def run(self):
        """Run the component."""
        try:
            if not self.initialize():
                self.logger.error("Failed to initialize component")
                return False
                
            self.start()
            self._running = True
            self.logger.info("Component started successfully")
            
            # Keep the main thread alive
            while self._running:
                try:
                    # Check for shutdown condition
                    if self._shutdown_event and self._shutdown_event.is_set():
                        break
                        
                    # Sleep to prevent high CPU usage
                    import time
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    self.logger.info("Received keyboard interrupt, shutting down...")
                    break
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}", exc_info=True)
                    time.sleep(5)  # Prevent tight loop on error
            
            return True
            
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            return False
        finally:
            self.stop()
            self.logger.info("Component stopped")
