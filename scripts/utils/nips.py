"""
NIPS Service Manager

This module provides the Network Intrusion Prevention System (NIPS) service manager for the SIEM system.
"""
import logging
from typing import Dict, Any, Optional
from .base_service import BaseService

logger = logging.getLogger('siem.nips')

class NIPSService(BaseService):
    """Network Intrusion Prevention System (NIPS) service manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NIPS service manager.
        
        Args:
            config: Configuration dictionary (typically from siem_config['nips'])
        """
        super().__init__(name='nips')
        self.config = config or {}
        
    def start(self) -> bool:
        """Start the NIPS service.
        
        Returns:
            bool: True if the service started successfully, False otherwise
        """
        if self.running:
            logger.warning("NIPS service is already running")
            return True
            
        try:
            logger.info("Starting NIPS service")
            # Initialize NIPS service here
            self.running = True
            logger.info("NIPS service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start NIPS service: {e}", exc_info=True)
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the NIPS service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("NIPS service is not running")
            return True
            
        try:
            logger.info("Stopping NIPS service")
            # Clean up NIPS service here
            self.running = False
            logger.info("NIPS service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping NIPS service: {e}", exc_info=True)
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the NIPS service.
        
        Returns:
            dict: Status information
        """
        return {
            'running': self.running,
            'config': self.config,
            'service_name': self.name,
            'status': 'running' if self.running else 'stopped'
        }
