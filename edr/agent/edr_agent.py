"""
EDR Agent Core
-------------
Core implementation of the Endpoint Detection and Response agent.
"""
import time
import json
import logging
import socket
import getpass
import uuid
import os
from enum import Enum, auto
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any, Union
from pathlib import Path

# Local imports
from edr.monitoring.system_monitor import SystemMonitor, SystemEvent

# Configure logging
logger = logging.getLogger('edr.agent')

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
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.agent_id = f"{self.hostname}-{uuid.uuid4().hex[:8]}"
        self.events: List[EDREvent] = []
        self.callbacks = {
            'event': [],
            'metrics': [],
            'start': [],
            'stop': []
        }
        self._load_config()
        
        # Initialize system monitor
        self.system_monitor = SystemMonitor({
            'watch_paths': self.config.get('watch_paths', [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ])
        })
        self.system_monitor.register_callback(self._handle_system_event)
        
    def _load_config(self) -> None:
        """Load configuration from file, environment variables, or use defaults.
        
        Priority order:
        1. Configuration passed to constructor
        2. Environment variables (EDR_*)
        3. Configuration file (edr_config.json in current directory)
        4. Default configuration
        """
        # Default configuration
        default_config = {
            'log_level': 'INFO',
            'log_file': 'edr_agent.log',
            'watch_paths': [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ],
            'scan_interval': 300,  # 5 minutes
            'max_event_age': 86400,  # 24 hours
            'enable_network_monitoring': True,
            'enable_file_monitoring': True,
            'enable_process_monitoring': True
        }
        
        # Initialize with defaults
        if not self.config:
            self.config = {}
            
        # Load from environment variables
        for key, default in default_config.items():
            env_key = f'EDR_{key.upper()}'
            if env_key in os.environ:
                env_value = os.environ[env_key]
                
                # Handle different types appropriately
                if isinstance(default, bool):
                    # Handle boolean values (true/false, yes/no, 1/0)
                    self.config[key] = env_value.lower() in ('true', 'yes', '1')
                elif isinstance(default, int):
                    # Handle integer values
                    try:
                        self.config[key] = int(env_value)
                    except ValueError:
                        logger.warning(f"Invalid integer value for {env_key}, using default: {default}")
                        self.config[key] = default
                elif isinstance(default, list):
                    # Handle lists (comma-separated values)
                    if env_value.startswith('[') and env_value.endswith(']'):
                        # Try to parse as JSON array
                        try:
                            self.config[key] = json.loads(env_value)
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON array for {env_key}, using default")
                            self.config[key] = default.copy()
                    else:
                        # Handle as comma-separated values
                        self.config[key] = [v.strip() for v in env_value.split(',')]
                else:
                    # Default to string
                    self.config[key] = env_value
        
        # Load from config file if it exists
        config_file = Path('edr_config.json')
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    # Merge file config with existing config (file takes precedence)
                    self.config = {**default_config, **file_config, **self.config}
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error loading config file: {e}")
                # If we can't load the file, use defaults
                self.config = {**default_config, **self.config}
        else:
            # If no config file, use defaults merged with any provided config
            self.config = {**default_config, **self.config}
            
        # Ensure required paths exist
        for path in self.config.get('watch_paths', []):
            try:
                Path(path).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create watch path {path}: {e}")
        
        # Configure logging
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['log_file']),
                logging.StreamHandler()
            ]
        )
        
        # Set default values if not provided
        self.config.setdefault('checkin_interval', 300)  # 5 minutes
        self.config.setdefault('max_offline_time', 900)  # 15 minutes
    
    def _handle_system_event(self, system_event: SystemEvent):
        """Handle system events from the system monitor."""
        try:
            # Map system event to EDR event
            event_data = {
                'event_type': system_event.event_type,
                'timestamp': system_event.timestamp,
                'severity': getattr(EventSeverity, system_event.severity, EventSeverity.INFO),
                'source': 'SystemMonitor',
                'details': system_event.data,
                'agent_id': self.agent_id,
                'hostname': self.hostname,
                'user': self.username
            }
            
            # Add process info if available
            if 'pid' in system_event.data:
                event_data['process_id'] = system_event.data['pid']
                if 'process_name' in system_event.data:
                    event_data['process_name'] = system_event.data['process_name']
            
            # Create and add the event
            event = EDREvent(
                event_id=str(uuid.uuid4()),
                **event_data
            )
            
            self.add_event(event)
            
        except Exception as e:
            logger.error(f"Error handling system event: {e}", exc_info=True)
    
    def start(self) -> bool:
        """Start the EDR agent."""
        if self.running:
            logger.warning("EDR agent is already running")
            return False
            
        logger.info("Starting EDR agent...")
        self.running = True
        self.start_time = time.time()
        
        try:
            # Start system monitoring
            self.system_monitor.start()
            
            # Initialize components
            self._initialize_components()
            
            # Generate initial status event
            self.add_event(EDREvent(
                event_id=str(uuid.uuid4()),
                event_type='AGENT_START',
                timestamp=time.time(),
                severity=EventSeverity.INFO,
                source='EDR Agent',
                details={'message': 'EDR Agent started successfully'},
                agent_id=self.agent_id,
                hostname=self.hostname,
                user=self.username
            ))
            
            # Notify callbacks
            for callback in self.callbacks['start']:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Error in start callback: {e}")
            
            logger.info("EDR agent started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start EDR agent: {e}", exc_info=True)
            self.running = False
            return False
        
    def _generate_test_events(self):
        """Generate test events for demonstration purposes."""
        import uuid
        import socket
        import getpass
        
        # Get system info
        hostname = socket.gethostname()
        username = getpass.getuser()
        
        # Sample events
        test_events = [
            {
                'event_type': 'AGENT_START',
                'severity': EventSeverity.INFO,
                'source': 'EDR Agent',
                'details': {'message': 'EDR Agent started successfully'}
            },
            {
                'event_type': 'PROCESS_CREATE',
                'severity': EventSeverity.LOW,
                'source': 'Process Monitor',
                'process_name': 'explorer.exe',
                'process_id': 1234,
                'details': {
                    'command_line': 'C:\\Windows\\explorer.exe',
                    'user': username,
                    'integrity_level': 'Medium'
                }
            },
            {
                'event_type': 'NETWORK_CONNECTION',
                'severity': EventSeverity.MEDIUM,
                'source': 'Network Monitor',
                'process_name': 'chrome.exe',
                'process_id': 5678,
                'details': {
                    'remote_ip': '192.168.1.100',
                    'remote_port': 443,
                    'protocol': 'TCP',
                    'domain': 'example.com'
                }
            },
            {
                'event_type': 'FILE_CREATE',
                'severity': EventSeverity.HIGH,
                'source': 'File Monitor',
                'process_name': 'powershell.exe',
                'process_id': 9012,
                'details': {
                    'path': 'C:\\temp\\suspicious.ps1',
                    'user': username,
                    'file_size': 1024
                }
            }
        ]
        
        # Add test events
        for event_data in test_events:
            event = EDREvent(
                event_id=str(uuid.uuid4()),
                timestamp=time.time(),
                agent_id=hostname,
                user=username,
                hostname=hostname,
                **event_data
            )
            self.add_event(event)
    
    def stop(self) -> bool:
        """Stop the EDR agent."""
        if not self.running:
            logger.warning("EDR agent is not running")
            return False
            
        logger.info("Stopping EDR agent...")
        self.running = False
        
        try:
            # Stop system monitoring
            self.system_monitor.stop()
            
            # Clean up components
            self._cleanup_components()
            
            # Generate stop event
            self.add_event(EDREvent(
                event_id=str(uuid.uuid4()),
                event_type='AGENT_STOP',
                timestamp=time.time(),
                severity=EventSeverity.INFO,
                source='EDR Agent',
                details={'message': 'EDR Agent stopped'},
                agent_id=self.agent_id,
                hostname=self.hostname,
                user=self.username
            ))
            
            # Notify callbacks
            for callback in self.callbacks['stop']:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Error in stop callback: {e}")
            
            logger.info("EDR agent stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping EDR agent: {e}", exc_info=True)
            return False
    
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
