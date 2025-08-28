"""
Collector Manager for the SIEM system.
Manages multiple log collectors and aggregates their output.
"""
import logging
from typing import Dict, List, Any, Type, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import signal
import sys

from .base import BaseCollector

class CollectorManager:
    """Manages multiple log collectors and aggregates their output."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the collector manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger("siem.collector.manager")
        self.collectors: Dict[str, BaseCollector] = {}
        self.running = False
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 5),
            thread_name_prefix='siem_collector_'
        )
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def add_collector(self, collector_id: str, collector_class: Type[BaseCollector], 
                     collector_config: Dict[str, Any] = None) -> None:
        """Add a new collector.
        
        Args:
            collector_id: Unique identifier for the collector
            collector_class: Collector class (subclass of BaseCollector)
            collector_config: Configuration for the collector
        """
        if collector_id in self.collectors:
            self.logger.warning(f"Collector {collector_id} already exists, replacing")
        
        try:
            collector = collector_class(collector_config or {})
            self.collectors[collector_id] = collector
            self.logger.info(f"Added collector: {collector_id} ({collector_class.__name__})")
        except Exception as e:
            self.logger.error(f"Failed to initialize collector {collector_id}: {e}")
            raise
    
    def remove_collector(self, collector_id: str) -> bool:
        """Remove a collector.
        
        Args:
            collector_id: ID of the collector to remove
            
        Returns:
            True if collector was removed, False if not found
        """
        if collector_id in self.collectors:
            collector = self.collectors.pop(collector_id)
            try:
                collector.stop()
            except Exception as e:
                self.logger.error(f"Error stopping collector {collector_id}: {e}")
            return True
        return False
    
    def start(self) -> None:
        """Start all collectors."""
        if self.running:
            self.logger.warning("Collector manager is already running")
            return
        
        self.running = True
        for collector_id, collector in self.collectors.items():
            try:
                collector.start()
                self.logger.info(f"Started collector: {collector_id}")
            except Exception as e:
                self.logger.error(f"Failed to start collector {collector_id}: {e}")
                
        self.logger.info(f"Collector manager started with {len(self.collectors)} collectors")
    
    def stop(self) -> None:
        """Stop all collectors and clean up resources."""
        if not self.running:
            return
            
        self.logger.info("Stopping collector manager...")
        self.running = False
        
        # Stop all collectors
        for collector_id, collector in self.collectors.items():
            try:
                collector.stop()
                self.logger.info(f"Stopped collector: {collector_id}")
            except Exception as e:
                self.logger.error(f"Error stopping collector {collector_id}: {e}")
        
        # Shutdown the executor
        self.executor.shutdown(wait=True)
        self.logger.info("Collector manager stopped")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
