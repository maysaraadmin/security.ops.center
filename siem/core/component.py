"""
Base Component Class

This module defines the base Component class that all SIEM components inherit from.
"""
import logging
from typing import Any, Dict, Optional

class Component:
    """Base class for all SIEM components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the component with configuration.
        
        Args:
            config: Dictionary containing component configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__module__)
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the component."""
        if not self._initialized:
            self._initialized = True
            self.logger.info(f"Initialized {self.__class__.__name__}")
    
    def start(self) -> None:
        """Start the component."""
        if not self._initialized:
            self.initialize()
        self.logger.info(f"Started {self.__class__.__name__}")
    
    def stop(self) -> None:
        """Stop the component."""
        self.logger.info(f"Stopped {self.__class__.__name__}")
    
    def status(self) -> Dict[str, Any]:
        """Get the status of the component.
        
        Returns:
            Dictionary containing status information
        """
        return {
            "name": self.__class__.__name__,
            "initialized": self._initialized,
            "config": self.config
        }
