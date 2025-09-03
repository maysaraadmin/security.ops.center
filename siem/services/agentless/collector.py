"""
Agentless Collector Service
--------------------------
Service implementation for agentless log collection.
"""
import asyncio
import logging
import signal
import sys
from typing import Dict, Any, Optional

# Configure logging
logger = logging.getLogger('siem.services.agentless.collector')

class AgentlessCollectorService:
    """Service wrapper for the agentless collector."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the agentless collector service.
        
        Args:
            config: Configuration dictionary for the collector
        """
        self.config = config
        self.running = False
        self.collector = None
        self.loop = None
        
    async def start(self):
        """Start the agentless collector service."""
        if self.running:
            logger.warning("Agentless collector is already running")
            return
            
        logger.info("Starting agentless collector service")
        
        try:
            from siem.collectors.agentless import AgentlessCollector
            
            self.collector = AgentlessCollector(self.config)
            await self.collector.start()
            self.running = True
            logger.info("Agentless collector service started successfully")
            
            # Keep the service running
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start agentless collector: {e}", exc_info=True)
            raise
            
    async def stop(self):
        """Stop the agentless collector service."""
        if not self.running:
            return
            
        logger.info("Stopping agentless collector service")
        self.running = False
        
        if self.collector:
            await self.collector.stop()
            
        logger.info("Agentless collector service stopped")
        
    async def get_status(self) -> Dict[str, Any]:
        """Get the current status of the collector.
        
        Returns:
            Dictionary containing status information
        """
        if not self.collector:
            return {
                'status': 'not_running',
                'message': 'Collector not initialized'
            }
            
        # Get connected devices if available
        connected_devices = {}
        if hasattr(self.collector, 'get_connected_devices'):
            try:
                devices = self.collector.get_connected_devices()
                if asyncio.iscoroutine(devices):
                    connected_devices = await devices
                else:
                    connected_devices = devices
            except Exception as e:
                logger.error(f"Error getting connected devices: {e}", exc_info=True)
                connected_devices = {}
        
        return {
            'status': 'running' if self.running else 'stopped',
            'connected_devices': connected_devices
        }
