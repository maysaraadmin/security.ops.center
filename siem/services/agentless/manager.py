"""
Agentless Service Manager
------------------------
Manages the lifecycle of agentless collection services.
"""
import asyncio
import logging
from typing import Dict, Any, Optional

from .collector import AgentlessCollectorService

logger = logging.getLogger('siem.services.agentless.manager')

class AgentlessServiceManager:
    """Manages agentless collection services."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the agentless service manager.
        
        Args:
            config: Configuration dictionary for the agentless services
        """
        self.config = config
        self.collector_service = None
        self.running = False
        
    async def start(self):
        """Start all agentless services."""
        if self.running:
            logger.warning("Agentless services are already running")
            return
            
        logger.info("Starting agentless services")
        self.running = True
        
        # Start the collector service
        self.collector_service = AgentlessCollectorService(self.config.get('collector', {}))
        await self.collector_service.start()
        
    async def stop(self):
        """Stop all agentless services."""
        if not self.running:
            return
            
        logger.info("Stopping agentless services")
        
        if self.collector_service:
            await self.collector_service.stop()
            
        self.running = False
        logger.info("Agentless services stopped")
        
    def get_status(self) -> Dict[str, Any]:
        """Get the status of all agentless services.
        
        Returns:
            Dictionary containing status information for all services
        """
        status = {
            'status': 'running' if self.running else 'stopped',
            'services': {}
        }
        
        if self.collector_service:
            status['services']['collector'] = self.collector_service.get_status()
            
        return status
        
    async def get_connected_devices(self) -> Dict[str, Any]:
        """Get information about connected devices.
        
        Returns:
            Dictionary containing information about connected devices
        """
        if not self.collector_service or not self.running:
            return {}
            
        return self.collector_service.get_status().get('connected_devices', {})
