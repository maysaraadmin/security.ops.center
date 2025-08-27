"""
Base Component Class

This module defines the base Component class that all SIEM components should inherit from.
"""

import abc
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class Component(abc.ABC):
    """Abstract base class for all SIEM components."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the component with the given configuration.
        
        Args:
            config: Dictionary containing component configuration
        """
        self.config = config
        self.running = False
        self.name = self.__class__.__name__
    
    @abc.abstractmethod
    def start(self) -> None:
        """Start the component.
        
        This method should be implemented by subclasses to start the component's
        main functionality.
        """
        pass
    
    @abc.abstractmethod
    def stop(self) -> None:
        """Stop the component.
        
        This method should be implemented by subclasses to cleanly shut down
        the component.
        """
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the component.
        
        Returns:
            Dictionary containing status information
        """
        return {
            'name': self.name,
            'running': self.running,
            'config': self.config
        }
    
    def __str__(self) -> str:
        """Return a string representation of the component."""
        return f"{self.name}(running={self.running})"
    
    def __repr__(self) -> str:
        """Return a string representation of the component."""
        return f"<{self.name} running={self.running}>"
