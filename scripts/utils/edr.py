"""
EDR Service Manager

This module provides the EDR service manager for the SIEM system.
"""
import logging
from typing import Dict, Any, Optional

from .edr_service import EDRService
from .base_service import BaseService

logger = logging.getLogger('siem.edr')

class EDRManager(BaseService):
    """Endpoint Detection and Response (EDR) service manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the EDR service manager.
        
        Args:
            config: Configuration dictionary (typically from siem_config['edr'])
        """
        super().__init__(name='edr')
        self.config = config or {}
        self.service = None
        
    def start(self) -> bool:
        """Start the EDR service.
        
        Returns:
            bool: True if the service started successfully, False otherwise
        """
        if self.running:
            logger.warning("EDR service is already running")
            return True
            
        try:
            logger.info("Starting EDR service")
            self.service = EDRService(config=self.config)
            self.service.start()
            self.running = True
            logger.info("EDR service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start EDR service: {e}", exc_info=True)
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the EDR service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise
        """
        if not self.running or not self.service:
            logger.warning("EDR service is not running")
            return True
            
        try:
            logger.info("Stopping EDR service")
            self.service.stop()
            self.running = False
            logger.info("EDR service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping EDR service: {e}", exc_info=True)
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the EDR service.
        
        Returns:
            dict: Status information
        """
        return {
            'running': self.running,
            'config': self.config,
            'service_name': self.name,
            'status': 'running' if self.running else 'stopped'
        }
