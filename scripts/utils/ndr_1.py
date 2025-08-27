"""
NDR Service Manager

This module provides the NDR service manager for the SIEM system.
"""
import logging
from typing import Dict, Any, Optional
from .base_service import BaseService

logger = logging.getLogger('siem.ndr')

class NDRManager(BaseService):
    """Network Detection and Response (NDR) service manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NDR service manager.
        
        Args:
            config: Configuration dictionary (typically from siem_config['ndr'])
        """
        super().__init__(name='ndr')
        self.config = config or {}
        
    def start(self) -> bool:
        """Start the NDR service.
        
        Returns:
            bool: True if the service started successfully, False otherwise
        """
        if self.running:
            logger.warning("NDR service is already running")
            return True
            
        try:
            logger.info("Starting NDR service")
            # Initialize NDR service here
            self.running = True
            logger.info("NDR service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start NDR service: {e}", exc_info=True)
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the NDR service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("NDR service is not running")
            return True
            
        try:
            logger.info("Stopping NDR service")
            # Clean up NDR service here
            self.running = False
            logger.info("NDR service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping NDR service: {e}", exc_info=True)
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the NDR service.
        
        Returns:
            dict: Status information
        """
        return {
            'running': self.running,
            'config': self.config,
            'service_name': self.name,
            'status': 'running' if self.running else 'stopped'
        }
