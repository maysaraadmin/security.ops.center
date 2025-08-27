from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

class BaseService(ABC):
    """Base class for all SIEM services."""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f'siem.service.{name.lower()}')
        self.is_running = False
    
    @abstractmethod
    def start(self) -> bool:
        """Start the service."""
        pass
    
    @abstractmethod
    def stop(self) -> bool:
        """Stop the service."""
        pass
    
    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """Get the current status of the service."""
        pass
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name}, running={self.is_running})"
