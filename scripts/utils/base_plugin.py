"""
Base Plugin for SIEM Components

This module provides a base class for all SIEM plugins.
"""
import time
import threading
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class PluginStatus:
    """Represents the status of a SIEM plugin."""
    name: str
    status: str  # 'running', 'stopped', 'error'
    events_processed: int = 0
    alerts_triggered: int = 0
    last_error: Optional[str] = None
    uptime: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert status to dictionary."""
        return asdict(self)

class BasePlugin:
    """Base class for all SIEM plugins."""
    
    def __init__(self, name: str):
        self.name = name
        self.status = PluginStatus(name=name, status='stopped')
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._start_time: float = 0.0
        
    def start(self) -> bool:
        """Start the plugin."""
        if self._thread and self._thread.is_alive():
            return False
            
        self._stop_event.clear()
        self.status.status = 'starting'
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True
        
    def stop(self) -> bool:
        """Stop the plugin."""
        if not self._thread or not self._thread.is_alive():
            return False
            
        self._stop_event.set()
        self._thread.join(timeout=5.0)
        self.status.status = 'stopped'
        return True
        
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the plugin."""
        self.status.uptime = time.time() - self._start_time if self._start_time > 0 else 0.0
        return self.status.to_dict()
        
    def _run(self):
        """Main plugin loop. Override this in subclasses."""
        self.status.status = 'running'
        
        try:
            self.on_start()
            while not self._stop_event.is_set():
                self.update_metrics()
                self._stop_event.wait(1.0)
        except Exception as e:
            self.status.status = 'error'
            self.status.last_error = str(e)
        finally:
            self.on_stop()
            self.status.status = 'stopped'
    
    def on_start(self):
        """Called when the plugin starts. Override in subclasses."""
        pass
        
    def on_stop(self):
        """Called when the plugin stops. Override in subclasses."""
        pass
        
    def update_metrics(self):
        """Update plugin metrics. Override in subclasses."""
        pass
        
    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single event.
        
        Args:
            event: The event to process
            
        Returns:
            Optional[Dict[str, Any]]: The processed event, or None if the event should be filtered out
        """
        return event
        
    def generate_alert(self, event: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """
        Generate an alert from an event.
        
        Args:
            event: The event that triggered the alert
            reason: The reason for the alert
            
        Returns:
            Dict[str, Any]: The generated alert
        """
        return {
            'timestamp': time.time(),
            'plugin': self.name,
            'event': event,
            'reason': reason,
            'severity': 'medium'
        }
