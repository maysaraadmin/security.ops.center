from typing import Dict, Any, Type, Optional, List
from .base_service import BaseService
import logging

class ServiceManager:
    """Manages the lifecycle of all SIEM services."""
    
    def __init__(self):
        self.services: Dict[str, BaseService] = {}
        self.logger = logging.getLogger('siem.service.manager')
    
    def register_service(self, service: BaseService) -> bool:
        """Register a new service."""
        if service.name in self.services:
            self.logger.warning(f"Service '{service.name}' is already registered")
            return False
        
        self.services[service.name] = service
        self.logger.info(f"Registered service: {service.name}")
        return True
    
    def start_service(self, name: str) -> bool:
        """Start a specific service by name."""
        service = self.services.get(name)
        if not service:
            self.logger.error(f"Service '{name}' not found")
            return False
        
        try:
            self.logger.info(f"Starting service: {name}")
            return service.start()
        except Exception as e:
            self.logger.error(f"Failed to start service '{name}': {str(e)}")
            return False
    
    def stop_service(self, name: str) -> bool:
        """Stop a specific service by name."""
        service = self.services.get(name)
        if not service:
            self.logger.error(f"Service '{name}' not found")
            return False
        
        try:
            self.logger.info(f"Stopping service: {name}")
            return service.stop()
        except Exception as e:
            self.logger.error(f"Failed to stop service '{name}': {str(e)}")
            return False
    
    def start_all(self) -> Dict[str, bool]:
        """Start all registered services."""
        results = {}
        for name in self.services:
            results[name] = self.start_service(name)
        return results
    
    def stop_all(self) -> Dict[str, bool]:
        """Stop all registered services in reverse order."""
        results = {}
        for name in reversed(list(self.services.keys())):
            results[name] = self.stop_service(name)
        return results
    
    def get_service(self, name: str) -> Optional[BaseService]:
        """Get a service by name."""
        return self.services.get(name)
    
    def get_all_services(self) -> List[BaseService]:
        """Get all registered services."""
        return list(self.services.values())
    
    def get_service_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Get the status of a specific service."""
        service = self.get_service(name)
        if not service:
            return None
        return service.status()
    
    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get the status of all services."""
        return {name: service.status() for name, service in self.services.items()}
    
    def is_service_running(self, name: str) -> bool:
        """Check if a service is running."""
        service = self.get_service(name)
        if not service:
            return False
        return service.is_running
