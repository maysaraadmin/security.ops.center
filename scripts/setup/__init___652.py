"""
Interfaces for core SIEM components.

This module defines abstract base classes and interfaces that form the foundation
of the SIEM system's component architecture.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class Service(ABC):
    """Base interface for all SIEM services."""
    
    @abstractmethod
    def start(self) -> bool:
        """Start the service.
        
        Returns:
            bool: True if the service started successfully, False otherwise.
        """
        pass
    
    @abstractmethod
    def stop(self) -> bool:
        """Stop the service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise.
        """
        pass
    
    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """Get the current status of the service.
        
        Returns:
            Dict[str, Any]: A dictionary containing status information.
        """
        pass

class ServiceManager(ABC):
    """Interface for service management."""
    
    @abstractmethod
    def register_service(self, name: str, service: Service) -> bool:
        """Register a new service.
        
        Args:
            name: The name of the service.
            service: The service instance to register.
            
        Returns:
            bool: True if the service was registered successfully.
        """
        pass
    
    @abstractmethod
    def get_service(self, name: str) -> Optional[Service]:
        """Get a registered service by name.
        
        Args:
            name: The name of the service to retrieve.
            
        Returns:
            Optional[Service]: The service instance, or None if not found.
        """
        pass
    
    @abstractmethod
    def start_service(self, name: str) -> bool:
        """Start a registered service.
        
        Args:
            name: The name of the service to start.
            
        Returns:
            bool: True if the service started successfully.
        """
        pass
    
    @abstractmethod
    def stop_service(self, name: str) -> bool:
        """Stop a registered service.
        
        Args:
            name: The name of the service to stop.
            
        Returns:
            bool: True if the service stopped successfully.
        """
        pass
