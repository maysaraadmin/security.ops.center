"""Base manager class for SIEM system managers."""
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger('siem.managers.base')


class BaseManager:
    """Base class for all manager classes in the SIEM system.
    
    This class provides common functionality and interface for all managers.
    """
    
    def __init__(self, **kwargs: Any):
        """Initialize the base manager.
        
        Args:
            **kwargs: Additional keyword arguments for specific manager implementations.
        """
        self.logger = logging.getLogger(f'siem.managers.{self.__class__.__name__.lower()}')
        self._initialized = False
        self._running = False
    
    def initialize(self) -> None:
        """Initialize the manager.
        
        This method should be overridden by subclasses to perform any necessary
        initialization, such as setting up database connections or loading configurations.
        """
        if self._initialized:
            self.logger.warning("Manager already initialized")
            return
        
        self.logger.info("Initializing manager")
        self._initialized = True
    
    def start(self) -> None:
        """Start the manager.
        
        This method should be overridden by subclasses to start any background
        processes or threads.
        """
        if not self._initialized:
            self.initialize()
        
        if self._running:
            self.logger.warning("Manager already running")
            return
        
        self.logger.info("Starting manager")
        self._running = True
    
    def stop(self) -> None:
        """Stop the manager.
        
        This method should be overridden by subclasses to cleanly stop any
        background processes or threads.
        """
        if not self._running:
            self.logger.warning("Manager not running")
            return
        
        self.logger.info("Stopping manager")
        self._running = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the manager.
        
        Returns:
            A dictionary containing status information about the manager.
        """
        return {
            'initialized': self._initialized,
            'running': self._running,
            'manager_type': self.__class__.__name__,
        }
    
    def __del__(self) -> None:
        """Ensure the manager is properly cleaned up."""
        if self._running:
            try:
                self.stop()
            except Exception as e:
                self.logger.error(f"Error during cleanup: {e}", exc_info=True)
