"""
Logging and Forensics Module for HIPS

Records process executions, file changes, and network connections for incident response.
Integrates with SIEM for centralized threat analysis.
"""

import os
import sys
import json
import time
import socket
import logging
import datetime
import threading
import traceback
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import hashlib
import platform
import psutil
import uuid

# Try to import required modules
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import win32security
    import win32api
    import win32con
    WINDOWS_SPECIFIC = True
except ImportError:
    WINDOWS_SPECIFIC = False

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Types of security events that can be logged."""
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTEN = "network_listen"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    SECURITY_ALERT = "security_alert"
    CONFIG_CHANGE = "config_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE_DETECTION = "malware_detection"

class Severity(Enum):
    """Severity levels for security events."""
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Event:
    """Base class for all security events."""
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    hostname: str = field(default_factory=socket.gethostname)
    source: str = "hips"
    severity: Severity = Severity.INFORMATIONAL
    details: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.name
        data['@timestamp'] = datetime.datetime.utcfromtimestamp(
            self.timestamp
        ).isoformat() + 'Z'
        return data

@dataclass
class ProcessEvent(Event):
    """Event for process-related activities."""
    process_id: Optional[int] = None
    parent_id: Optional[int] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize process-specific fields."""
        if self.process_id and not self.process_name:
            try:
                proc = psutil.Process(self.process_id)
                self.process_name = proc.name()
                self.command_line = ' '.join(proc.cmdline()) if proc.cmdline() else None
                
                if not self.user:
                    try:
                        self.user = proc.username()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

@dataclass
class FileEvent(Event):
    """Event for file system activities."""
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_extension: Optional[str] = None
    file_owner: Optional[str] = None
    file_permissions: Optional[str] = None
    file_hash: Optional[str] = None
    old_path: Optional[str] = None
    
    def __post_init__(self):
        """Initialize file-specific fields."""
        if self.file_path:
            self.file_name = os.path.basename(self.file_path)
            _, ext = os.path.splitext(self.file_path)
            self.file_extension = ext.lower() if ext else None
            
            try:
                if os.path.exists(self.file_path):
                    self.file_size = os.path.getsize(self.file_path)
                    if not self.file_hash:
                        self.file_hash = self._calculate_file_hash(self.file_path)
            except (OSError, PermissionError):
                pass
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None

@dataclass
class NetworkEvent(Event):
    """Event for network activities."""
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    
    def __post_init__(self):
        """Initialize network-specific fields."""
        if self.process_id and not self.process_name:
            try:
                self.process_name = psutil.Process(self.process_id).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

class SIEMForwarder:
    """Handles forwarding events to SIEM systems."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the SIEM forwarder."""
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.endpoints = self.config.get('endpoints', [])
        self.batch_size = self.config.get('batch_size', 100)
        self.batch_timeout = self.config.get('batch_timeout', 5.0)
        self.queue: List[Dict[str, Any]] = []
        self.last_flush = time.time()
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # Start background thread for batch processing
        self.worker_thread = threading.Thread(
            target=self._batch_worker,
            daemon=True
        )
        self.worker_thread.start()
    
    def forward(self, event: Union[Event, Dict]) -> bool:
        """Forward an event to configured SIEM endpoints."""
        if not self.enabled or not self.endpoints:
            return False
        
        # Convert Event to dict if needed
        if isinstance(event, Event):
            event_data = event.to_dict()
        else:
            event_data = event
        
        # Add to queue
        with self.lock:
            self.queue.append(event_data)
            
            # Flush if batch size reached
            if len(self.queue) >= self.batch_size:
                return self._flush_queue()
                
        return True
    
    def _batch_worker(self):
        """Background worker for batch processing."""
        while not self._stop_event.is_set():
            try:
                # Check if we should flush based on timeout
                time_since_flush = time.time() - self.last_flush
                if time_since_flush >= self.batch_timeout and self.queue:
                    self._flush_queue()
                
                # Sleep for a short time to prevent high CPU usage
                self._stop_event.wait(0.1)
                
            except Exception as e:
                logger.error(f"Error in SIEM batch worker: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def _flush_queue(self) -> bool:
        """Flush the event queue to all configured endpoints."""
        if not self.queue:
            return True
        
        with self.lock:
            # Get current batch
            batch = list(self.queue[:self.batch_size])
            self.queue = self.queue[self.batch_size:]
            
            if not batch:
                return True
            
            success = True
            
            # Send to each endpoint
            for endpoint in self.endpoints:
                try:
                    if not self._send_to_endpoint(endpoint, batch):
                        success = False
                except Exception as e:
                    logger.error(f"Error sending to SIEM endpoint {endpoint.get('url')}: {e}")
                    success = False
            
            self.last_flush = time.time()
            return success
    
    def _send_to_endpoint(self, endpoint: Dict, batch: List[Dict]) -> bool:
        """Send a batch of events to a specific SIEM endpoint."""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests module not available, cannot send to SIEM")
            return False
            
        url = endpoint.get('url')
        if not url:
            return False
            
        headers = endpoint.get('headers', {})
        auth = endpoint.get('auth')
        verify_ssl = endpoint.get('verify_ssl', True)
        
        # Add default content type if not specified
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        try:
            # Handle different authentication methods
            auth_obj = None
            if auth:
                auth_type = auth.get('type', 'basic')
                if auth_type == 'basic' and 'username' in auth and 'password' in auth:
                    from requests.auth import HTTPBasicAuth
                    auth_obj = HTTPBasicAuth(auth['username'], auth['password'])
                elif auth_type == 'bearer' and 'token' in auth:
                    headers['Authorization'] = f"Bearer {auth['token']}"
            
            # Prepare request data based on endpoint configuration
            data_format = endpoint.get('format', 'json')
            if data_format == 'json':
                data = batch[0] if len(batch) == 1 and endpoint.get('single_event', False) else batch
                response = requests.post(
                    url,
                    json=data,
                    headers=headers,
                    auth=auth_obj,
                    verify=verify_ssl,
                    timeout=endpoint.get('timeout', 10.0)
                )
            else:
                # Handle other formats (e.g., syslog, CEF, LEEF)
                # This is a simplified example - in practice, you'd need to implement
                # proper formatting for each log format
                log_lines = []
                for event in batch:
                    if data_format == 'cef':
                        log_lines.append(self._format_cef(event))
                    elif data_format == 'leef':
                        log_lines.append(self._format_leef(event))
                    else:  # syslog
                        log_lines.append(json.dumps(event))
                
                response = requests.post(
                    url,
                    data='\n'.join(log_lines),
                    headers=headers,
                    auth=auth_obj,
                    verify=verify_ssl,
                    timeout=endpoint.get('timeout', 10.0)
                )
            
            # Check response status
            if response.status_code >= 400:
                logger.error(
                    f"SIEM endpoint returned error: {response.status_code} - {response.text}"
                )
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error sending to SIEM endpoint {url}: {e}")
            return False
    
    def _format_cef(self, event: Dict) -> str:
        """Format an event as CEF (Common Event Format)."""
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        version = "0"
        device_vendor = "HIPS"
        device_product = "SecurityModule"
        device_version = "1.0"
        signature_id = event.get('event_id', '0')
        name = event.get('event_type', 'unknown')
        severity = str(event.get('severity', '0'))
        
        # Build extension
        ext_parts = []
        for key, value in event.items():
            if key not in ['event_type', 'event_id', 'severity']:
                if isinstance(value, (str, int, float, bool)):
                    ext_parts.append(f"{key}={value}")
                elif value is not None:
                    ext_parts.append(f"{key}={json.dumps(value)}")
        
        extension = ' '.join(ext_parts)
        
        return f"CEF:{version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension}"
    
    def _format_leef(self, event: Dict) -> str:
        """Format an event as LEEF (Log Event Extended Format)."""
        # LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Key1=Value1\tKey2=Value2
        version = "2.0"
        vendor = "HIPS"
        product = "SecurityModule"
        product_version = "1.0"
        event_id = event.get('event_type', 'unknown')
        
        # Build attributes
        attrs = []
        for key, value in event.items():
            if key != 'event_type':
                if isinstance(value, (str, int, float, bool)):
                    attrs.append(f"{key}={value}")
                elif value is not None:
                    attrs.append(f"{key}={json.dumps(value)}")
        
        attributes = '\t'.join(attrs)
        
        return f"LEEF:{version}|{vendor}|{product}|{product_version}|{event_id}|{attributes}"
    
    def stop(self):
        """Stop the SIEM forwarder and flush any remaining events."""
        self._stop_event.set()
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5.0)
        self._flush_queue()

class ForensicsLogger:
    """Main class for logging and forwarding security events."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the forensics logger."""
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.log_file = self.config.get('log_file')
        self.max_log_size = self.config.get('max_log_size', 10 * 1024 * 1024)  # 10 MB default
        self.max_log_backups = self.config.get('max_log_backups', 5)
        self.siem_forwarder = SIEMForwarder(self.config.get('siem', {}))
        self.event_handlers: List[Callable[[Dict], None]] = []
        
        # Set up file logging if configured
        self._setup_file_logging()
    
    def _setup_file_logging(self):
        """Set up file-based logging if configured."""
        if not self.log_file:
            return
            
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(os.path.abspath(self.log_file))
            os.makedirs(log_dir, exist_ok=True)
            
            # Configure file handler with rotation
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_file,
                maxBytes=self.max_log_size,
                backupCount=self.max_log_backups,
                encoding='utf-8'
            )
            
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            
            logger.addHandler(file_handler)
            logger.info("File logging initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize file logging: {e}")
    
    def log_event(self, event: Union[Event, Dict], forward_to_siem: bool = True) -> bool:
        """Log a security event."""
        if not self.enabled:
            return False
        
        try:
            # Convert Event to dict if needed
            if isinstance(event, Event):
                event_data = event.to_dict()
            else:
                event_data = event
            
            # Log to file if configured
            if self.log_file:
                try:
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(event_data) + '\n')
                except (IOError, OSError) as e:
                    logger.error(f"Failed to write to log file: {e}")
            
            # Forward to SIEM if enabled
            if forward_to_siem:
                self.siem_forwarder.forward(event_data)
            
            # Call registered event handlers
            for handler in self.event_handlers:
                try:
                    handler(event_data)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}", exc_info=True)
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging event: {e}", exc_info=True)
            return False
    
    def add_event_handler(self, handler: Callable[[Dict], None]):
        """Add a custom event handler."""
        if handler not in self.event_handlers:
            self.event_handlers.append(handler)
    
    def remove_event_handler(self, handler: Callable[[Dict], None]):
        """Remove an event handler."""
        if handler in self.event_handlers:
            self.event_handlers.remove(handler)
    
    def stop(self):
        """Stop the forensics logger and clean up resources."""
        self.siem_forwarder.stop()
        logger.info("Forensics logger stopped")

# Example usage
if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Configuration
    config = {
        'enabled': True,
        'log_file': '/var/log/hips/security_events.log',
        'max_log_size': 10 * 1024 * 1024,  # 10 MB
        'max_log_backups': 5,
        'siem': {
            'enabled': True,
            'endpoints': [
                {
                    'url': 'http://siem.example.com/api/events',
                    'format': 'json',
                    'auth': {
                        'type': 'basic',
                        'username': 'api_user',
                        'password': 'api_password'
                    },
                    'verify_ssl': True
                },
                {
                    'url': 'udp://syslog.example.com:514',
                    'format': 'cef',
                    'verify_ssl': False
                }
            ]
        }
    }
    
    # Create forensics logger
    forensics = ForensicsLogger(config)
    
    # Example event handlers
    def alert_on_high_severity(event):
        if event.get('severity') in ['HIGH', 'CRITICAL']:
            print(f"[!] SECURITY ALERT: {event.get('event_type')} - {event.get('details', {})}")
    
    # Add event handler
    forensics.add_event_handler(alert_on_high_severity)
    
    # Example: Log a process creation event
    process_event = ProcessEvent(
        event_type=EventType.PROCESS_CREATE,
        process_id=1234,
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="DOMAIN\\user",
        severity=Severity.MEDIUM,
        details={
            "parent_process": "explorer.exe",
            "integrity_level": "High",
            "hashes": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
    )
    
    # Log the event
    forensics.log_event(process_event)
    
    print("Forensics logging example complete. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        forensics.stop()
        print("\nForensics logger stopped")
