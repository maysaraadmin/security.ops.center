"""
Windows Event Collector for SIEM

This module implements a Windows Event Collector that receives and processes
Windows Event Log entries from remote Windows machines.
"""
import asyncio
import logging
import yaml
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Union
from pathlib import Path

from ..parsers import windows_events

logger = logging.getLogger('siem.collector.wec')

class WindowsEventCollector:
    """Windows Event Collector for receiving and processing Windows Event Logs."""
    
    def __init__(self, config_path: str = None, callback: Callable[[Dict[str, Any]], None] = None):
        """Initialize the Windows Event Collector.
        
        Args:
            config_path: Path to the configuration file
            callback: Function to call with processed events
        """
        self.config = self._load_config(config_path)
        self.callback = callback
        self.running = False
        self._event_queue = asyncio.Queue()
        self._stats = {
            'events_received': 0,
            'events_processed': 0,
            'errors': 0,
            'start_time': datetime.utcnow(),
            'last_error': None
        }
        
        # Initialize parser
        self.parser = windows_events.parse_windows_event
        
        # Set up logging
        self._setup_logging()
        
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load configuration from file."""
        default_config = {
            'enabled': True,
            'server': '0.0.0.0',
            'port': 5985,
            'ssl_enabled': False,
            'auth_method': 'ntlm',
            'subscription_name': 'SIEM-Collection',
            'channels': [
                {'name': 'Security', 'query': '*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]'},
                {'name': 'System', 'query': '*[System[(Level=1 or Level=2 or Level=3)]]'}
            ],
            'batch_size': 50,
            'max_batch_latency': 30,
            'log_level': 'INFO'
        }
        
        if not config_path:
            return default_config
            
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if 'wec' in config:
                    return {**default_config, **config['wec']}
                return default_config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            return default_config
            
    def _setup_logging(self):
        """Set up logging configuration."""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.config.get('log_file', 'wec_collector.log'))
            ]
        )
        
    async def start(self):
        """Start the Windows Event Collector."""
        if not self.config.get('enabled', True):
            logger.info("Windows Event Collector is disabled in configuration")
            return
            
        self.running = True
        logger.info(f"Starting Windows Event Collector on {self.config['server']}:{self.config['port']}")
        
        # Start the event processing loop
        self._processing_task = asyncio.create_task(self._process_events())
        
        # Start the statistics reporter
        self._stats_task = asyncio.create_task(self._report_stats())
        
        # Start the subscription manager
        await self._start_subscription_manager()
        
    async def stop(self):
        """Stop the Windows Event Collector."""
        self.running = False
        
        # Cancel all running tasks
        if hasattr(self, '_processing_task'):
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
                
        if hasattr(self, '_stats_task'):
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass
                
        logger.info("Windows Event Collector stopped")
        
    async def _start_subscription_manager(self):
        """Start the subscription manager for Windows Event Forwarding."""
        # This would be implemented to manage WEF subscriptions
        # For now, we'll just log that we're starting
        logger.info("Starting Windows Event Forwarding subscription manager")
        
    async def _process_events(self):
        """Process events from the queue."""
        batch = []
        last_flush = datetime.utcnow()
        
        while self.running:
            try:
                # Wait for an event with a timeout
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=1.0
                    )
                    batch.append(event)
                    self._stats['events_received'] += 1
                except asyncio.TimeoutError:
                    event = None
                
                # Check if we should flush the batch
                should_flush = (
                    len(batch) >= self.config.get('batch_size', 50) or
                    (datetime.utcnow() - last_flush).total_seconds() >= self.config.get('max_batch_latency', 30)
                )
                
                if should_flush and batch:
                    await self._process_batch(batch)
                    batch = []
                    last_flush = datetime.utcnow()
                    
            except Exception as e:
                self._stats['errors'] += 1
                self._stats['last_error'] = str(e)
                logger.error(f"Error processing events: {e}", exc_info=True)
                
    async def _process_batch(self, events: List[Dict[str, Any]]):
        """Process a batch of events."""
        if not events or not self.callback:
            return
            
        try:
            # Process each event in the batch
            for event in events:
                try:
                    # Parse and normalize the event
                    parsed = self.parser(event)
                    if parsed:
                        # Add metadata
                        parsed['@metadata'] = {
                            'received_at': datetime.utcnow().isoformat() + 'Z',
                            'collector': 'windows_event_collector',
                            'source_type': 'windows_event_log'
                        }
                        
                        # Call the callback with the parsed event
                        self.callback(parsed)
                        self._stats['events_processed'] += 1
                        
                except Exception as e:
                    self._stats['errors'] += 1
                    self._stats['last_error'] = str(e)
                    logger.error(f"Error processing event: {e}", exc_info=True)
                    
        except Exception as e:
            self._stats['errors'] += 1
            self._stats['last_error'] = str(e)
            logger.error(f"Error processing batch: {e}", exc_info=True)
            
    async def _report_stats(self):
        """Periodically report statistics."""
        while self.running:
            try:
                uptime = datetime.utcnow() - self._stats['start_time']
                logger.info(
                    f"WEC Stats - Uptime: {uptime}, "
                    f"Received: {self._stats['events_received']}, "
                    f"Processed: {self._stats['events_processed']}, "
                    f"Errors: {self._stats['errors']}"
                )
                
                if self._stats['errors'] > 0:
                    logger.warning(f"Last error: {self._stats['last_error']}")
                    
            except Exception as e:
                logger.error(f"Error reporting stats: {e}", exc_info=True)
                
            await asyncio.sleep(60)  # Report every minute
            
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the collector."""
        return {
            'running': self.running,
            'uptime': str(datetime.utcnow() - self._stats['start_time']),
            'events_received': self._stats['events_received'],
            'events_processed': self._stats['events_processed'],
            'errors': self._stats['errors'],
            'queue_size': self._event_queue.qsize(),
            'last_error': self._stats['last_error']
        }

# Example usage
if __name__ == "__main__":
    async def example_callback(event):
        """Example callback function for processing events."""
        print(f"Received event: {event.get('event_id')} - {event.get('event_type')}")
    
    async def main():
        # Create and start the collector
        collector = WindowsEventCollector(
            config_path='config/windows_event_collector.yaml',
            callback=example_callback
        )
        
        try:
            await collector.start()
            
            # Keep the collector running
            while True:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            print("Shutting down...")
            await collector.stop()
    
    asyncio.run(main())
