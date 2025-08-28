"""
Monitoring Service

This module implements the monitoring component of the SIEM system.
"""

import time
import threading
import psutil
import logging
from typing import Dict, Any

# Try absolute import first, fall back to relative if needed
try:
    from siem.core.component import Component
except ImportError:
    from .core.component import Component

logger = logging.getLogger(__name__)

class MonitoringService(Component):
    """Monitors system resources and SIEM component health."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the monitoring service.
        
        Args:
            config: Dictionary containing monitoring configuration
        """
        super().__init__(config)
        self.interval = config.get('interval', 60)  # seconds
        self.metrics = {}
        self._stop_event = threading.Event()
        self._monitor_thread = None
    
    def _collect_metrics(self) -> None:
        """Collect system and application metrics."""
        try:
            # System metrics
            self.metrics['cpu_percent'] = psutil.cpu_percent(interval=1)
            self.metrics['memory'] = dict(psutil.virtual_memory()._asdict())
            self.metrics['disk_usage'] = dict(psutil.disk_usage('/')._asdict())
            
            # Process metrics
            process = psutil.Process()
            self.metrics['process'] = {
                'memory_info': dict(process.memory_info()._asdict()),
                'cpu_percent': process.cpu_percent(interval=1),
                'threads': process.num_threads(),
                'connections': len(process.connections())
            }
            
            logger.debug(f"Collected metrics: {self.metrics}")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}", exc_info=True)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        logger.info("Starting monitoring loop")
        
        while not self._stop_event.is_set():
            try:
                self._collect_metrics()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
            
            # Wait for the next interval or until stopped
            self._stop_event.wait(self.interval)
        
        logger.info("Monitoring loop stopped")
    
    def start(self) -> None:
        """Start the monitoring service."""
        if self.running:
            logger.warning("Monitoring service is already running")
            return
            
        logger.info("Starting monitoring service")
        self.running = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="MonitoringThread",
            daemon=True
        )
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop the monitoring service."""
        if not self.running:
            return
            
        logger.info("Stopping monitoring service")
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
            
        self.running = False
        logger.info("Monitoring service stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the monitoring service.
        
        Returns:
            Dictionary containing status information
        """
        status = super().get_status()
        status.update({
            'metrics': self.metrics,
            'thread_alive': self._monitor_thread.is_alive() if self._monitor_thread else False
        })
        return status
