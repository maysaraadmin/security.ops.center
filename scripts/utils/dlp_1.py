"""
DLP Service Manager

This module provides the Data Loss Prevention (DLP) service manager for the SIEM system.
"""
import logging
from typing import Dict, Any, Optional
from .base_service import BaseService

logger = logging.getLogger('siem.dlp')

class DLPService(BaseService):
    """Data Loss Prevention (DLP) service manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the DLP service manager.
        
        Args:
            config: Configuration dictionary (typically from siem_config['dlp'])
        """
        super().__init__(name='dlp')
        self.config = config or {}
        
    def start(self) -> bool:
        """Start the DLP service.
        
        Returns:
            bool: True if the service started successfully, False otherwise
        """
        if self.running:
            logger.warning("DLP service is already running")
            return True
            
        try:
            logger.info("Starting DLP service")
            # Initialize DLP service here
            self.running = True
            logger.info("DLP service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start DLP service: {e}", exc_info=True)
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the DLP service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("DLP service is not running")
            return True
            
        try:
            logger.info("Stopping DLP service")
            # Clean up DLP service here
            self.running = False
            logger.info("DLP service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping DLP service: {e}", exc_info=True)
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the DLP service.
        
        Returns:
            dict: Status information
        """
        return {
            'running': self.running,
            'config': self.config,
            'service_name': self.name,
            'status': 'running' if self.running else 'stopped'
        }
