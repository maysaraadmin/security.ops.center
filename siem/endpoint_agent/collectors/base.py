"""
Base Collector
-------------
Abstract base class for all SIEM agent collectors.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger('siem_agent.collector')

class BaseCollector(ABC):
    """Base class for all SIEM agent collectors."""
    
    def __init__(self, name: str = None):
        """Initialize the collector.
        
        Args:
            name: Optional name for the collector. If not provided, the class name will be used.
        """
        self.name = name or self.__class__.__name__
        self.running = False
        self.last_run = None
        self._buffer = []
    
    def start(self):
        """Start the collector."""
        if self.running:
            logger.warning(f"{self.name} collector is already running")
            return
        
        self.running = True
        logger.info(f"Started {self.name} collector")
    
    def stop(self):
        """Stop the collector."""
        if not self.running:
            return
        
        self.running = False
        logger.info(f"Stopped {self.name} collector")
    
    def get_logs(self) -> List[Dict[str, Any]]:
        """Get collected logs and clear the internal buffer.
        
        Returns:
            List of log entries as dictionaries
        """
        try:
            if not self.running:
                self.start()
            
            # Get new logs
            self._collect()
            
            # Return and clear the buffer
            logs = list(self._buffer)
            self._buffer.clear()
            self.last_run = self._get_current_timestamp()
            
            if logs:
                logger.debug(f"Collected {len(logs)} logs from {self.name} collector")
                
            return logs
            
        except Exception as e:
            logger.error(f"Error in {self.name} collector: {e}", exc_info=True)
            return []
    
    @abstractmethod
    def _collect(self):
        """Collect logs and add them to the internal buffer.
        
        This method should be implemented by subclasses to collect specific types of logs.
        Collected logs should be added to self._buffer as dictionaries.
        """
        pass
    
    def _get_current_timestamp(self) -> str:
        """Get the current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def _add_log(self, log_data):
        """Add a log entry to the buffer.
        
        Args:
            log_data: Either a LogEntry object or a dictionary containing log data
        """
        if hasattr(log_data, 'to_dict'):
            # Handle LogEntry objects
            self._buffer.append(log_data)
        elif isinstance(log_data, dict):
            # Handle raw dictionaries
            self._buffer.append(log_data)
        else:
            logger.warning(f"Invalid log data type: {type(log_data)}, expected dict or LogEntry")
            return
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
