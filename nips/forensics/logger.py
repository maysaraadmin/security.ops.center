"""
Forensic Logger for NIPS

Provides structured logging of security events, attacks, and system activities.
"""
import logging
import logging.handlers
import json
import time
import os
import gzip
import zlib
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
import threading
import queue
import socket
import uuid
import sys

# Configure logging
class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Create a dict with the standard fields
        log_record = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'process': record.process,
            'thread': record.thread,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add any extra fields
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        
        return json.dumps(log_record, ensure_ascii=False)

class GZipRotator:
    """Rotate and compress log files with gzip."""
    
    def __call__(self, source: str, dest: str):
        """Rotate and compress the log file."""
        # Compress the source file
        with open(source, 'rb') as f_in:
            with gzip.open(f"{dest}.gz", 'wb') as f_out:
                f_out.writelines(f_in)
        
        # Remove the original file
        os.remove(source)

class ForensicLogger:
    """
    Centralized logging system for NIPS forensics.
    
    Features:
    - Structured JSON logging
    - Automatic log rotation and compression
    - Network logging support
    - Event deduplication
    - High-performance async logging
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the forensic logger.
        
        Args:
            config: Configuration dictionary with the following keys:
                - log_dir: Directory to store log files
                - max_size: Maximum log file size in MB before rotation (default: 100)
                - backup_count: Number of backup logs to keep (default: 30)
                - compress: Whether to compress rotated logs (default: True)
                - log_level: Logging level (default: INFO)
                - enable_console: Whether to log to console (default: True)
                - enable_syslog: Whether to enable syslog (default: False)
                - syslog_address: Syslog server address (default: localhost:514)
                - enable_network: Whether to enable network logging (default: False)
                - network_endpoints: List of network endpoints for log forwarding
        """
        self.config = config
        self.log_dir = Path(config.get('log_dir', '/var/log/nips/forensics'))
        self.max_size = config.get('max_size', 100) * 1024 * 1024  # Convert MB to bytes
        self.backup_count = config.get('backup_count', 30)
        self.compress = config.get('compress', True)
        self.log_level = getattr(logging, config.get('log_level', 'INFO'))
        self.enable_console = config.get('enable_console', True)
        self.enable_syslog = config.get('enable_syslog', False)
        self.syslog_address = config.get('syslog_address', ('localhost', 514))
        self.enable_network = config.get('enable_network', False)
        self.network_endpoints = config.get('network_endpoints', [])
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize logger
        self.logger = logging.getLogger('nips.forensics')
        self.logger.setLevel(self.log_level)
        
        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create formatter
        formatter = StructuredFormatter()
        
        # Add file handler with rotation
        log_file = self.log_dir / 'nips_forensics.log'
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=self.max_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Add console handler if enabled
        if self.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(console_handler)
        
        # Add syslog handler if enabled
        if self.enable_syslog:
            try:
                syslog_handler = logging.handlers.SysLogHandler(
                    address=self.syslog_address,
                    facility=logging.handlers.SysLogHandler.LOG_LOCAL0
                )
                syslog_handler.setFormatter(formatter)
                self.logger.addHandler(syslog_handler)
            except Exception as e:
                self.logger.error(f"Failed to initialize syslog handler: {e}")
        
        # Initialize network logging
        self.network_handlers = []
        if self.enable_network and self.network_endpoints:
            self._init_network_logging()
        
        # Initialize event deduplication
        self.event_cache = {}
        self.cache_lock = threading.Lock()
        self.cache_ttl = 3600  # 1 hour TTL for deduplication cache
        self.last_cache_cleanup = time.time()
        
        # Start background thread for log processing
        self.log_queue = queue.Queue()
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_log_queue, daemon=True)
        self.worker_thread.start()
        
        # Log initialization
        self.log(
            'SYSTEM',
            'Forensic logger initialized',
            {
                'log_dir': str(self.log_dir.absolute()),
                'log_level': logging.getLevelName(self.log_level),
                'max_size': f"{self.max_size / (1024*1024)}MB",
                'backup_count': self.backup_count,
                'compress': self.compress,
                'enable_console': self.enable_console,
                'enable_syslog': self.enable_syslog,
                'enable_network': self.enable_network,
                'hostname': socket.gethostname(),
                'pid': os.getpid()
            },
            level='INFO'
        )
    
    def _init_network_logging(self):
        """Initialize network logging handlers."""
        for endpoint in self.network_endpoints:
            try:
                if endpoint.startswith('tcp://'):
                    addr = endpoint[6:].split(':', 1)
                    if len(addr) == 2:
                        handler = logging.handlers.SocketHandler(addr[0], int(addr[1]))
                        self.network_handlers.append(handler)
                        self.logger.addHandler(handler)
                elif endpoint.startswith('udp://'):
                    addr = endpoint[6:].split(':', 1)
                    if len(addr) == 2:
                        handler = logging.handlers.DatagramHandler(addr[0], int(addr[1]))
                        self.network_handlers.append(handler)
                        self.logger.addHandler(handler)
                elif endpoint.startswith('file://'):
                    path = endpoint[7:]
                    handler = logging.FileHandler(path)
                    self.network_handlers.append(handler)
                    self.logger.addHandler(handler)
            except Exception as e:
                self.logger.error(f"Failed to initialize network logging to {endpoint}: {e}")
    
    def _process_log_queue(self):
        """Background thread to process log queue."""
        while self.running or not self.log_queue.empty():
            try:
                # Get log entry from queue with timeout to allow checking self.running
                try:
                    log_entry = self.log_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process the log entry
                self._write_log_entry(log_entry)
                
                # Clean up cache periodically
                if time.time() - self.last_cache_cleanup > 3600:  # Every hour
                    self._cleanup_cache()
                    self.last_cache_cleanup = time.time()
                
            except Exception as e:
                # Log the error to stderr to avoid infinite recursion
                print(f"Error in log processing thread: {e}", file=sys.stderr)
    
    def _write_log_entry(self, entry: Dict[str, Any]):
        """Write a log entry to all handlers."""
        # Create a log record
        record = logging.LogRecord(
            name=entry.get('logger', 'nips.forensics'),
            level=entry.get('levelno', logging.INFO),
            pathname=entry.get('pathname', ''),
            lineno=entry.get('lineno', 0),
            msg=entry.get('message', ''),
            args=(),
            exc_info=None,
            func=entry.get('funcName', '')
        )
        
        # Add extra fields
        record.extra = {k: v for k, v in entry.items() 
                       if k not in ('logger', 'levelno', 'pathname', 'lineno', 'message', 'funcName')}
        
        # Handle the record
        for handler in self.logger.handlers:
            if handler.level <= record.levelno:
                try:
                    handler.emit(record)
                except Exception as e:
                    print(f"Error emitting log record: {e}", file=sys.stderr)
    
    def _cleanup_cache(self):
        """Clean up expired entries from the deduplication cache."""
        now = time.time()
        with self.cache_lock:
            self.event_cache = {
                k: v for k, v in self.event_cache.items() 
                if now - v['timestamp'] < self.cache_ttl
            }
    
    def _generate_event_id(self, event_type: str, data: Dict[str, Any]) -> str:
        """Generate a unique ID for an event to detect duplicates."""
        # Create a hash of the event data for deduplication
        event_str = json.dumps({
            'type': event_type,
            'data': {k: v for k, v in data.items() if k not in ('timestamp', 'event_id')}
        }, sort_keys=True)
        return hashlib.md5(event_str.encode('utf-8')).hexdigest()
    
    def log(self, 
            event_type: str, 
            message: str, 
            data: Optional[Dict[str, Any]] = None,
            level: str = 'INFO',
            dedupe_ttl: int = 300) -> str:
        """
        Log a forensic event.
        
        Args:
            event_type: Type of event (e.g., 'ATTACK', 'ALERT', 'SYSTEM')
            message: Human-readable message
            data: Additional event data
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            dedupe_ttl: Time in seconds to consider this event as duplicate
            
        Returns:
            Event ID
        """
        if data is None:
            data = {}
        
        # Generate event ID for deduplication
        event_id = self._generate_event_id(event_type, data)
        
        # Check for duplicates
        with self.cache_lock:
            if event_id in self.event_cache:
                # Update timestamp of existing event
                self.event_cache[event_id]['count'] += 1
                self.event_cache[event_id]['timestamp'] = time.time()
                return event_id
            
            # Add new event to cache
            self.event_cache[event_id] = {
                'timestamp': time.time(),
                'count': 1
            }
        
        # Prepare log entry
        log_entry = {
            'event_id': event_id,
            'event_type': event_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': message,
            'level': level.upper(),
            'levelno': getattr(logging, level.upper(), logging.INFO),
            'logger': f"nips.forensics.{event_type.lower()}",
            'hostname': socket.gethostname(),
            'pid': os.getpid(),
            **data
        }
        
        # Add to processing queue
        self.log_queue.put(log_entry)
        
        return event_id
    
    def log_attack(self, 
                  attack_type: str, 
                  source_ip: str, 
                  target_ip: str, 
                  details: Dict[str, Any],
                  severity: str = 'MEDIUM') -> str:
        """
        Log a security attack.
        
        Args:
            attack_type: Type of attack (e.g., 'SQL_INJECTION', 'XSS', 'BRUTE_FORCE')
            source_ip: Source IP address of the attack
            target_ip: Target IP address
            details: Additional attack details
            severity: Attack severity (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            Event ID
        """
        return self.log(
            event_type=f'ATTACK_{attack_type}',
            message=f"{attack_type} attack detected from {source_ip} to {target_ip}",
            data={
                'source_ip': source_ip,
                'target_ip': target_ip,
                'severity': severity.upper(),
                'attack_details': details
            },
            level='WARNING' if severity.upper() in ('LOW', 'MEDIUM') else 'ERROR'
        )
    
    def log_alert(self, 
                 alert_type: str, 
                 message: str, 
                 details: Dict[str, Any],
                 severity: str = 'MEDIUM') -> str:
        """
        Log a security alert.
        
        Args:
            alert_type: Type of alert
            message: Alert message
            details: Additional alert details
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            Event ID
        """
        return self.log(
            event_type=f'ALERT_{alert_type}',
            message=message,
            data={
                'severity': severity.upper(),
                'alert_details': details
            },
            level='WARNING' if severity.upper() in ('LOW', 'MEDIUM') else 'ERROR'
        )
    
    def log_forensic(self, 
                    event_type: str, 
                    message: str, 
                    evidence: Dict[str, Any],
                    tags: Optional[List[str]] = None) -> str:
        """
        Log forensic evidence.
        
        Args:
            event_type: Type of forensic event
            message: Description of the evidence
            evidence: Evidence data
            tags: Optional list of tags for categorization
            
        Returns:
            Event ID
        """
        if tags is None:
            tags = []
            
        return self.log(
            event_type=f'FORENSIC_{event_type}',
            message=message,
            data={
                'evidence': evidence,
                'tags': tags
            },
            level='INFO'
        )
    
    def shutdown(self):
        """Shut down the logger and wait for all logs to be processed."""
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=10)
        
        # Close all handlers
        for handler in self.logger.handlers[:]:
            try:
                handler.close()
            except Exception as e:
                print(f"Error closing handler: {e}", file=sys.stderr)
        
        # Clear handlers
        self.logger.handlers.clear()
        
        # Log shutdown
        print("Forensic logger shut down", file=sys.stderr)

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'log_dir': './logs',
        'max_size': 10,  # 10MB
        'backup_count': 5,
        'compress': True,
        'log_level': 'DEBUG',
        'enable_console': True,
        'enable_syslog': False,
        'enable_network': False,
        'network_endpoints': [
            'tcp://logstash:5000',
            'udp://splunk:514'
        ]
    }
    
    # Create logger
    logger = ForensicLogger(config)
    
    try:
        # Example logs
        logger.log("SYSTEM", "Starting NIPS forensics system", {"version": "1.0.0"})
        
        # Log an attack
        logger.log_attack(
            attack_type="SQL_INJECTION",
            source_ip="192.168.1.100",
            target_ip="10.0.0.10",
            details={
                "query": "SELECT * FROM users WHERE username='admin' OR '1'='1' --",
                "method": "POST",
                "path": "/login",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            severity="HIGH"
        )
        
        # Log forensic evidence
        logger.log_forensic(
            event_type="FILE_DOWNLOAD",
            message="Suspicious file download detected",
            evidence={
                "filename": "malware.exe",
                "source": "http://evil.com/malware.exe",
                "destination": "C:\\Users\\victim\\Downloads\\malware.exe",
                "size": 1024000,
                "hash": "a1b2c3d4e5f6..."
            },
            tags=["malware", "download"]
        )
        
    finally:
        # Shut down the logger
        logger.shutdown()
