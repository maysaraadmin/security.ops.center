"""
Windows Events Integration for SIEM

This module integrates Windows Event Collection with the main SIEM application.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from ..collectors.windows_event_collector import WindowsEventCollector
from ..event_processor import EventProcessor

logger = logging.getLogger('siem.integration.windows_events')

class WindowsEventsIntegration:
    """Windows Events Integration for SIEM."""
    
    def __init__(self, event_processor: EventProcessor, config: Dict[str, Any]):
        """Initialize the Windows Events integration.
        
        Args:
            event_processor: The SIEM's event processor
            config: Configuration dictionary
        """
        self.event_processor = event_processor
        self.config = config
        self.collector = None
        self.running = False
        
    async def start(self):
        """Start the Windows Events integration."""
        if not self.config.get('enabled', True):
            logger.info("Windows Events integration is disabled")
            return
            
        logger.info("Starting Windows Events integration")
        
        # Create and start the Windows Event Collector
        self.collector = WindowsEventCollector(
            config_path=self.config.get('config_path'),
            callback=self._process_event
        )
        
        try:
            await self.collector.start()
            self.running = True
            logger.info("Windows Events integration started successfully")
        except Exception as e:
            logger.error(f"Failed to start Windows Events integration: {e}", exc_info=True)
            raise
            
    async def stop(self):
        """Stop the Windows Events integration."""
        if not self.running or not self.collector:
            return
            
        logger.info("Stopping Windows Events integration")
        
        try:
            await self.collector.stop()
            self.running = False
            logger.info("Windows Events integration stopped")
        except Exception as e:
            logger.error(f"Error stopping Windows Events integration: {e}", exc_info=True)
            
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a Windows Event Log entry.
        
        Args:
            event: The parsed Windows Event Log entry
        """
        try:
            # Add metadata
            if '@metadata' not in event:
                event['@metadata'] = {}
                
            event['@metadata'].update({
                'source': 'windows_event_log',
                'collector': 'windows_event_collector',
                'received_at': datetime.utcnow().isoformat() + 'Z'
            })
            
            # Process the event through the SIEM's event processor
            if hasattr(self, 'event_processor') and hasattr(self.event_processor, 'process_event'):
                self.event_processor.process_event(event)
            
        except Exception as e:
            logger.error(f"Error processing Windows event: {e}", exc_info=True)
            
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the integration.
        
        Returns:
            Dict containing the current status of the integration
        """
        if not hasattr(self, 'collector') or not self.collector:
            return {
                'enabled': self.config.get('enabled', False),
                'running': False,
                'status': 'not_initialized',
                'events_received': 0,
                'events_processed': 0,
                'errors': 0,
                'queue_size': 0,
                'last_error': None
            }
            
        try:
            collector_status = self.collector.get_status()
            return {
                'enabled': self.config.get('enabled', False),
                'running': getattr(self, 'running', False),
                'status': 'running' if getattr(self, 'running', False) else 'stopped',
                'uptime': collector_status.get('uptime', '0:00:00'),
                'events_received': collector_status.get('events_received', 0),
                'events_processed': collector_status.get('events_processed', 0),
                'errors': collector_status.get('errors', 0),
                'queue_size': collector_status.get('queue_size', 0),
                'last_error': collector_status.get('last_error')
            }
        except Exception as e:
            logger.error(f"Error getting status: {e}", exc_info=True)
            return {
                'enabled': self.config.get('enabled', False),
                'running': False,
                'status': 'error',
                'error': str(e)
            }
