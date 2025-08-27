"""
Enhanced EDR Agent with detection and monitoring capabilities.
"""
import os
import time
import logging
import threading
import json
import platform
import psutil
from typing import Dict, List, Optional, Any, Callable, Union
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from enum import Enum

class EventSeverity(Enum):
    """Severity levels for events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SystemMetrics:
    """System metrics data class."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    processes: int
    boot_time: float = field(default_factory=lambda: psutil.boot_time())

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

class EDREvent:
    """Enhanced event class for EDR with severity and source tracking."""
    def __init__(self, 
                 event_type: str, 
                 data: dict,
                 severity: EventSeverity = EventSeverity.INFO,
                 source: str = None,
                 tags: List[str] = None):
        self.event_id = f"evt_{int(datetime.utcnow().timestamp() * 1000)}"
        self.event_type = event_type
        self.data = data
        self.timestamp = datetime.utcnow()
        self.severity = severity
        self.source = source or platform.node()
        self.tags = tags or []
        
    def to_dict(self) -> dict:
        """Convert event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'source': self.source,
            'tags': self.tags
        }

class EDRAgent:
    """Enhanced EDR Agent with monitoring and detection capabilities."""
    
    def __init__(self, config: dict = None):
        """Initialize the EDR agent with configuration."""
        self.config = config or {}
        self.running = False
        self.event_queue = []
        self.event_history = []
        self.metrics_history = []
        self.event_queue_lock = threading.Lock()
        self.metrics_lock = threading.Lock()
        self.max_history = self.config.get('max_history', 1000)
        
        # Callback registry
        self.callbacks = {
            'threat_detected': [],
            'event_received': [],
            'metrics_updated': [],
            'agent_started': [],
            'agent_stopped': []
        }
        
        # Initialize logging
        self.logger = logging.getLogger('edr.agent')
        self._setup_logging()
        
        # System monitoring
        self.monitoring_thread = None
        self.monitoring_interval = self.config.get('monitoring_interval', 5.0)
        
        self.logger.info("EDR Agent initialized")
        
    def _setup_logging(self):
        """Configure logging for the agent."""
        log_level = self.config.get('log_level', 'INFO').upper()
        log_file = self.config.get('log_file', 'edr_agent.log')
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def start(self) -> bool:
        """Start the EDR agent and monitoring."""
        if self.running:
            self.logger.warning("EDR Agent is already running")
            return False
            
        self.logger.info("Starting EDR Agent...")
        self.running = True
        
        # Start system monitoring
        self.monitoring_thread = threading.Thread(
            target=self._monitor_system,
            daemon=True
        )
        self.monitoring_thread.start()
        
        # Trigger callbacks
        self._trigger_callbacks('agent_started')
        self.logger.info("EDR Agent started successfully")
        return True
    
    def stop(self) -> bool:
        """Stop the EDR agent and clean up resources."""
        if not self.running:
            self.logger.warning("EDR Agent is not running")
            return False
            
        self.logger.info("Stopping EDR Agent...")
        self.running = False
        
        # Wait for monitoring thread to finish
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5.0)
            
        # Trigger callbacks
        self._trigger_callbacks('agent_stopped')
        self.logger.info("EDR Agent stopped")
        return True
    
    def register_callback(self, event_type: str, callback: Callable):
        """Register a callback for a specific event type."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
        else:
            self.logger.warning(f"Unknown event type: {event_type}")
    
    def _trigger_callbacks(self, event_type: str, *args, **kwargs):
        """Trigger all registered callbacks for an event type."""
        for callback in self.callbacks.get(event_type, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Error in {event_type} callback: {e}")
    
    def submit_event(self, event: Union[EDREvent, dict]):
        """Submit an event to the EDR agent for processing."""
        if isinstance(event, dict):
            event = EDREvent(
                event_type=event.get('event_type', 'unknown'),
                data=event.get('data', {}),
                severity=EventSeverity(event.get('severity', 'INFO')),
                source=event.get('source'),
                tags=event.get('tags', [])
            )
            
        with self.event_queue_lock:
            self.event_queue.append(event)
            # Add to history
            self.event_history.append(event)
            # Trim history if needed
            if len(self.event_history) > self.max_history:
                self.event_history = self.event_history[-self.max_history:]
                
        self.logger.debug(f"Event submitted: {event.event_type} (ID: {event.event_id})")
        self._trigger_callbacks('event_received', event)
        return event.event_id
    
    def get_queued_events(self, clear: bool = True) -> List[EDREvent]:
        """Get all queued events and optionally clear the queue.
        
        Args:
            clear: If True, clears the event queue after retrieval
            
        Returns:
            List of EDREvent objects
        """
        with self.event_queue_lock:
            events = self.event_queue.copy()
            if clear:
                self.event_queue.clear()
        return events
        
    def get_event_history(self, limit: int = 100) -> List[EDREvent]:
        """Get recent events from history.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of recent EDREvent objects
        """
        return self.event_history[-limit:]
        
    def get_metrics_history(self, limit: int = 60) -> List[SystemMetrics]:
        """Get recent system metrics.
        
        Args:
            limit: Maximum number of metrics to return
            
        Returns:
            List of SystemMetrics objects
        """
        with self.metrics_lock:
            return self.metrics_history[-limit:]
            
    def _monitor_system(self):
        """Monitor system metrics in a background thread."""
        self.logger.info("Starting system monitoring")
        
        while self.running:
            try:
                # Collect system metrics
                metrics = SystemMetrics(
                    timestamp=time.time(),
                    cpu_percent=psutil.cpu_percent(interval=1),
                    memory_percent=psutil.virtual_memory().percent,
                    disk_percent=psutil.disk_usage('/').percent,
                    network_bytes_sent=psutil.net_io_counters().bytes_sent,
                    network_bytes_recv=psutil.net_io_counters().bytes_recv,
                    processes=len(psutil.pids())
                )
                
                # Store metrics
                with self.metrics_lock:
                    self.metrics_history.append(metrics)
                    if len(self.metrics_history) > self.max_history:
                        self.metrics_history = self.metrics_history[-self.max_history:]
                
                # Trigger callbacks
                self._trigger_callbacks('metrics_updated', metrics)
                
                # Sleep until next interval
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in system monitoring: {e}")
                time.sleep(5)  # Prevent tight loop on errors
                
    def get_status(self) -> dict:
        """Get current agent status."""
        return {
            'running': self.running,
            'queued_events': len(self.event_queue),
            'total_events': len(self.event_history),
            'callbacks': {k: len(v) for k, v in self.callbacks.items()},
            'monitoring_interval': self.monitoring_interval,
            'start_time': min([e.timestamp for e in self.event_history], default=None),
            'system': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'process_id': os.getpid()
            }
        }
