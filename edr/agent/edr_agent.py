"""
EDR Agent Core
-------------
Core implementation of the Endpoint Detection and Response agent.
"""
import time
import json
import logging
from enum import Enum, auto
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

class EventSeverity(Enum):
    """Severity levels for EDR events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class EDREvent:
    """Represents a security event detected by the EDR agent."""
    event_id: str
    event_type: str
    timestamp: float
    severity: EventSeverity
    source: str
    details: Dict[str, Any]
    agent_id: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        result = asdict(self)
        result['severity'] = self.severity.value
        result['timestamp'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return result
    
    def to_json(self) -> str:
        """Convert the event to a JSON string."""
        return json.dumps(self.to_dict())

class EDRAgent:
    """
    Main EDR (Endpoint Detection and Response) agent class.
    
    This class handles the core functionality of the EDR agent, including
    event collection, processing, and response actions.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the EDR agent with the given configuration."""
        self.config = config or {}
        self.running = False
        self.start_time = time.time()
        self.events: List[EDREvent] = []
        self.callbacks = {
            'event': [],
            'metrics': [],
            'start': [],
            'stop': []
        }
        self._load_config()
        
    def _load_config(self) -> None:
        """Load configuration from file if not provided."""
        if not self.config:
            # Default configuration
            self.config = {
                'log_level': 'INFO',
                'log_file': 'edr_agent.log',
                'checkin_interval': 300,  # 5 minutes
                'max_offline_time': 900,  # 15 minutes
            }
    
    def start(self) -> bool:
        """Start the EDR agent."""
        if self.running:
            logger.warning("EDR agent is already running")
            return False
            
        logger.info("Starting EDR agent...")
        self.running = True
        self.start_time = time.time()
        
        # Initialize components
        self._initialize_components()
        
        # Notify callbacks
        for callback in self.callbacks['start']:
            try:
                callback()
            except Exception as e:
                logger.error(f"Error in start callback: {e}")
        
        logger.info("EDR agent started successfully")
        return True
    
    def stop(self) -> bool:
        """Stop the EDR agent."""
        if not self.running:
            logger.warning("EDR agent is not running")
            return False
            
        logger.info("Stopping EDR agent...")
        self.running = False
        
        # Clean up resources
        self._cleanup_components()
        
        # Notify callbacks
        for callback in self.callbacks['stop']:
            try:
                callback()
            except Exception as e:
                logger.error(f"Error in stop callback: {e}")
        
        logger.info("EDR agent stopped successfully")
        return True
    
    def _initialize_components(self) -> None:
        """Initialize EDR components."""
        # Placeholder for component initialization
        logger.debug("Initializing EDR components...")
    
    def _cleanup_components(self) -> None:
        """Clean up EDR components."""
        # Placeholder for component cleanup
        logger.debug("Cleaning up EDR components...")
    
    def add_event(self, event: EDREvent) -> None:
        """
        Add a new security event to the event log.
        
        Args:
            event: The EDR event to add
        """
        self.events.append(event)
        
        # Notify event callbacks
        for callback in self.callbacks['event']:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")
    
    def get_events(self, limit: int = 100, **filters) -> List[EDREvent]:
        """
        Get a list of events, optionally filtered.
        
        Args:
            limit: Maximum number of events to return
            **filters: Filter criteria (e.g., severity='HIGH')
            
        Returns:
            List of matching EDREvent objects
        """
        events = self.events[-limit:]  # Get most recent events
        
        # Apply filters
        if filters:
            events = [
                e for e in events
                if all(
                    getattr(e, k, None) == v 
                    for k, v in filters.items()
                )
            ]
            
        return events
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current agent metrics.
        
        Returns:
            Dictionary containing agent metrics
        """
        metrics = {
            'status': 'running' if self.running else 'stopped',
            'uptime': time.time() - self.start_time,
            'event_count': len(self.events),
            'event_counts_by_severity': {
                level.name: sum(1 for e in self.events if e.severity == level)
                for level in EventSeverity
            },
            'last_event_time': (
                self.events[-1].timestamp if self.events else None
            ),
        }
        
        # Notify metrics callbacks
        for callback in self.callbacks['metrics']:
            try:
                metrics.update(callback(metrics) or {})
            except Exception as e:
                logger.error(f"Error in metrics callback: {e}")
        
        return metrics
    
    def register_callback(self, event_type: str, callback: Callable) -> None:
        """
        Register a callback function for agent events.
        
        Args:
            event_type: Type of event to register for ('event', 'metrics', 'start', 'stop')
            callback: Callback function to register
        """
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
        else:
            logger.warning(f"Unknown event type: {event_type}")
    
    def remove_callback(self, event_type: str, callback: Callable) -> None:
        """
        Remove a registered callback function.
        
        Args:
            event_type: Type of event to unregister from
            callback: Callback function to remove
        """
        if event_type in self.callbacks and callback in self.callbacks[event_type]:
            self.callbacks[event_type].remove(callback)
