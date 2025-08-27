"""
Service manager for the SIEM system.

This module provides the ServiceManager class that implements the ServiceManager interface
and manages the lifecycle of all SIEM services.
"""
import logging
import threading
from typing import Dict, Any, Optional, List, Type, TypeVar, Callable

from .interfaces import Service, ServiceManager as IServiceManager
from .base_service import BaseService

T = TypeVar('T', bound=BaseService)  # Type variable for service types

class ServiceManager(IServiceManager):
    """Manages the lifecycle of SIEM services.
    
    This class implements the ServiceManager interface and provides functionality
    to register, start, stop, and monitor SIEM services.
    """
    
    def __init__(self):
        """Initialize the service manager."""
        self.services: Dict[str, Service] = {}
        self._lock = threading.RLock()
        self.logger = logging.getLogger('siem.service_manager')
        self._service_status: Dict[str, Dict[str, Any]] = {}
    
    def register_service(self, name: str, service: Service) -> bool:
        """Register a service with the service manager.
        
        Args:
            name: The name of the service
            service: The service instance to register
            
        Returns:
            bool: True if the service was registered successfully
            
        Raises:
            ValueError: If the service name is invalid or already registered
        """
        if not name or not isinstance(name, str):
            raise ValueError("Service name must be a non-empty string")
            
        if not isinstance(service, Service):
            raise ValueError(f"Service must implement the Service interface: {name}")
            
        with self._lock:
            if name in self.services:
                self.logger.warning(f"Service '{name}' is already registered")
                return False
                
            self.services[name] = service
            self._service_status[name] = {
                'registered': True,
                'started': False,
                'last_error': None,
                'dependencies': []
            }
            self.logger.info(f"Registered service: {name}")
            return True
    
    def get_service(self, name: str) -> Optional[Service]:
        """Get a registered service by name.
        
        Args:
            name: The name of the service to retrieve
            
        Returns:
            Optional[Service]: The service instance, or None if not found
        """
        with self._lock:
            return self.services.get(name)
    
    def start_service(self, name: str, *args, **kwargs) -> bool:
        """Start a registered service.
        
        Args:
            name: The name of the service to start
            *args: Additional arguments to pass to the service's start method
            **kwargs: Additional keyword arguments to pass to the service's start method
            
        Returns:
            bool: True if the service started successfully or was already running
            
        Raises:
            ValueError: If the service is not registered
        """
        service = self.get_service(name)
        if not service:
            raise ValueError(f"Service '{name}' is not registered")
            
        with self._lock:
            if self._service_status[name]['started']:
                self.logger.debug(f"Service '{name}' is already running")
                return True
                
            try:
                self.logger.info(f"Starting service: {name}")
                if service.start(*args, **kwargs):
                    self._service_status[name]['started'] = True
                    self._service_status[name]['last_error'] = None
                    self.logger.info(f"Successfully started service: {name}")
                    return True
                else:
                    self.logger.error(f"Failed to start service: {name}")
                    return False
                    
            except Exception as e:
                self._service_status[name]['last_error'] = str(e)
                self.logger.error(f"Error starting service '{name}': {e}", exc_info=True)
                return False
    
    def stop_service(self, name: str, *args, **kwargs) -> bool:
        """Stop a registered service.
        
        Args:
            name: The name of the service to stop
            *args: Additional arguments to pass to the service's stop method
            **kwargs: Additional keyword arguments to pass to the service's stop method
            
        Returns:
            bool: True if the service was stopped successfully or was not running
            
        Raises:
            ValueError: If the service is not registered
        """
        service = self.get_service(name)
        if not service:
            raise ValueError(f"Service '{name}' is not registered")
            
        with self._lock:
            if not self._service_status[name]['started']:
                self.logger.debug(f"Service '{name}' is not running")
                return True
                
            try:
                self.logger.info(f"Stopping service: {name}")
                if service.stop(*args, **kwargs):
                    self._service_status[name]['started'] = False
                    self._service_status[name]['last_error'] = None
                    self.logger.info(f"Successfully stopped service: {name}")
                    return True
                else:
                    self.logger.error(f"Failed to stop service: {name}")
                    return False
                    
            except Exception as e:
                self._service_status[name]['last_error'] = str(e)
                self.logger.error(f"Error stopping service '{name}': {e}", exc_info=True)
                return False
    
    def get_service_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Get the status of a registered service.
        
        Args:
            name: The name of the service
            
        Returns:
            Optional[Dict[str, Any]]: The service status, or None if not found
            Optional[Dict]: Status dictionary if service exists, None otherwise
        """
        if name not in self.services:
            self.logger.warning(f"Service '{name}' is not registered")
            return None
            
        return self.services[name].status()
    
    def start_all(self) -> Dict[str, bool]:
        """Start all registered services.
        
        Returns:
            Dict[str, bool]: Dictionary mapping service names to start status
        """
        results = {}
        for name in self.services:
            results[name] = self.start_service(name)
        return results
    
    def stop_all(self) -> Dict[str, bool]:
        """Stop all running services.
        
        Returns:
            Dict[str, bool]: Dictionary mapping service names to stop status
        """
        results = {}
        for name in reversed(list(self.services.keys())):  # Stop in reverse order
            results[name] = self.stop_service(name)
        return results
    
    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get the status of all services.
        
        Returns:
            Dict[str, Dict]: Dictionary mapping service names to their status
        """
        return {name: service.status() for name, service in self.services.items()}
