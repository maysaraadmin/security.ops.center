"""
Base class for all EDR monitoring components.
"""
import abc
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import threading

class BaseMonitor(abc.ABC):
    """Abstract base class for all monitoring components."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the monitor with configuration."""
        self.config = config
        self.logger = logging.getLogger(f"edr.monitor.{self.__class__.__name__}")
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.event_handlers: List[Callable[[Dict[str, Any]], None]] = []
    
    def start(self) -> None:
        """Start the monitoring."""
        if self.running:
            self.logger.warning("Monitor is already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Started {self.__class__.__name__}")
    
    def stop(self) -> None:
        """Stop the monitoring."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        self.logger.info(f"Stopped {self.__class__.__name__}")
    
    def register_handler(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Register an event handler."""
        self.event_handlers.append(handler)
    
    def _notify_handlers(self, event: Dict[str, Any]) -> None:
        """Notify all registered handlers of an event."""
        for handler in self.event_handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Error in event handler: {e}", exc_info=True)
    
    @abc.abstractmethod
    def _monitor_loop(self) -> None:
        """Main monitoring loop. Subclasses must implement this."""
        pass
    
    def _create_event(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a standardized event dictionary."""
        return {
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'monitor': self.__class__.__name__,
            'data': data
        }
