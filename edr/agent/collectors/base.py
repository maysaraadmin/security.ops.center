"""
Base collector implementation for the EDR agent.
"""
import os
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger('edr.agent.collector.base')

class BaseCollector:
    """Base class for all collectors."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize the collector."""
        self.name = name
        self.config = config
        self.enabled = True
        self.interval = config.get('interval', 60)  # Default 60 seconds
        self.last_run = 0
        self._setup()
    
    def _setup(self) -> None:
        """Perform any necessary setup for this collector."""
        pass
    
    def collect(self) -> Dict[str, Any]:
        """Collect and return data from this collector.
        
        Returns:
            Dict containing the collected data.
        """
        if not self.enabled:
            return {}
            
        current_time = time.time()
        if current_time - self.last_run < self.interval:
            return {}
            
        try:
            start_time = time.time()
            data = self._collect()
            duration = time.time() - start_time
            
            if duration > 1.0:  # Log if collection took more than 1 second
                logger.warning(
                    f"Collector {self.name} took {duration:.2f}s to execute"
                )
                
            self.last_run = current_time
            return data
            
        except Exception as e:
            logger.error(f"Error in collector {self.name}: {e}", exc_info=True)
            return {}
    
    def _collect(self) -> Dict[str, Any]:
        """Implementation of the actual collection logic."""
        raise NotImplementedError("Subclasses must implement _collect()")
    
    def start(self) -> None:
        """Start the collector (for continuous collection)."""
        self.enabled = True
        logger.info(f"Started collector: {self.name}")
    
    def stop(self) -> None:
        """Stop the collector."""
        self.enabled = False
        logger.info(f"Stopped collector: {self.name}")
    
    def __str__(self) -> str:
        """String representation of the collector."""
        return f"{self.__class__.__name__}(name={self.name}, enabled={self.enabled})"
