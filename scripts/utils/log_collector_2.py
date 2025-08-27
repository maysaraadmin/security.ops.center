"""
Enhanced Log Collector Module

This module provides advanced log collection and normalization capabilities
for the SIEM system, supporting multiple log sources and formats.
"""

import os
import json
import yaml
import logging
import time
import re
import gzip
import shutil
import hashlib
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable, Tuple, TypeVar
from queue import Queue, Full
from threading import Thread, Event, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logging.handlers import RotatingFileHandler

T = TypeVar('T', Dict, List)

def deep_merge(base: T, update: T) -> T:
    """Recursively merge two dictionaries or lists.
    
    For dictionaries, keys in the update dict will overwrite those in base.
    For lists, the update list will be appended to the base list.
    
    Args:
        base: The base dictionary or list
        update: The dictionary or list to merge into base
        
    Returns:
        The merged result
    """
    if isinstance(base, dict) and isinstance(update, dict):
        result = base.copy()
        for key, value in update.items():
            if key in base and isinstance(base[key], (dict, list)) and isinstance(value, type(base[key])):
                result[key] = deep_merge(base[key], value)
            else:
                result[key] = value
        return result
    elif isinstance(base, list) and isinstance(update, list):
        return base + update
    return update

# Configure logging
logger = logging.getLogger('siem.log_collector')

class LogNormalizer:
    """Handles normalization of log data into a common schema with security features."""
    
    COMMON_SCHEMA = {
        'timestamp': None,
        'source': None,
        'event_type': None,
        'severity': 'info',
        'message': '',
        'raw': None,
        'tags': [],
        'source_ip': None,
        'destination_ip': None,
        'user': None,
        'process': None,
        'status': None
    }
    
    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = [
        (r'(?i)(password|passwd|pwd|secret|key|token|api[_-]?key|auth[_-]?token)=[^&\s]+', '[REDACTED]'),
        (r'(?i)(?:\b|_)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?)?key|token|auth(?:entication|orization)?)[=:][^\s,;\'"]+', '[REDACTED]'),
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b', '[CREDIT_CARD_REDACTED]'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]')
    ]
    
    @classmethod
    def _sanitize_sensitive_data(cls, data: Union[str, Dict]) -> Union[str, Dict]:
        """Sanitize sensitive data from log entries.
        
        Args:
            data: The data to sanitize (string or dictionary)
            
        Returns:
            Sanitized data with sensitive information redacted
        """
        if isinstance(data, str):
            sanitized = data
            for pattern, replacement in cls.SENSITIVE_PATTERNS:
                sanitized = re.sub(pattern, replacement, sanitized)
            return sanitized
            
        elif isinstance(data, dict):
            return {k: cls._sanitize_sensitive_data(v) for k, v in data.items()}
            
        return data
    
    def __init__(self, schema_mappings: Optional[Dict[str, Dict]] = None):
        """
        Initialize the log normalizer with optional custom schema mappings.
        
        Args:
            schema_mappings: Dictionary mapping log source types to their schema mappings
        """
        self.schema_mappings = schema_mappings or {}
        self.default_mappings = {
            'syslog': {
                'timestamp': ('timestamp', self._parse_timestamp),
                'host': 'source',
                'severity': ('severity', self._normalize_severity),
                'message': 'message',
                'process': 'process',
                'pid': 'pid'
            },
            'json': {
                'timestamp': ('@timestamp', self._parse_timestamp),
                'host': 'host',
                'source': 'source',
                'message': 'message',
                'level': ('severity', self._normalize_severity),
                'user': 'user',
                'source_ip': 'src_ip',
                'destination_ip': 'dst_ip',
                'event_type': 'event_type',
                'status': 'status'
            },
            'windows_event': {
                'timestamp': ('TimeGenerated', self._parse_timestamp),
                'source': ('SourceName', lambda x: f"win:{x}"),
                'event_id': 'event_id',
                'event_type': ('EventType', self._map_windows_event_type),
                'severity': ('Level', self._map_windows_severity),
                'message': 'Message',
                'user': 'User',
                'computer': 'Computer',
                'process': 'ProcessName',
                'process_id': 'ProcessId'
            }
        }
    
    def normalize(self, log_data: Union[str, Dict], source_type: str = 'auto') -> Dict:
        """
        Normalize log data to the common schema.
        
        Args:
            log_data: Raw log data (string or dictionary)
            source_type: Type of log source (e.g., 'syslog', 'json', 'windows_event')
            
        Returns:
            Normalized log entry as a dictionary
        """
        # Parse the log data if it's a string
        if isinstance(log_data, str):
            try:
                # Try to parse as JSON first
                log_data = json.loads(log_data)
                if source_type == 'auto':
                    source_type = 'json'
            except json.JSONDecodeError:
                # If not JSON, try to parse as syslog
                if source_type == 'auto':
                    source_type = 'syslog'
                    log_data = self._parse_syslog(log_data)
        
        # Get the appropriate mapping for the source type
        mapping = self.schema_mappings.get(source_type, {}) or self.default_mappings.get(source_type, {})
        
        # Create the normalized log entry
        normalized = self.COMMON_SCHEMA.copy()
        normalized['raw'] = log_data
        
        # Apply the mapping
        for target_field, source_spec in mapping.items():
            if isinstance(source_spec, tuple):
                source_field, transform = source_spec
            else:
                source_field, transform = source_spec, None
            
            if source_field in log_data:
                value = log_data[source_field]
                if transform and callable(transform):
                    try:
                        value = transform(value)
                    except Exception as e:
                        logger.warning(f"Error transforming field {source_field}: {e}")
                normalized[target_field] = value
        
        # Set defaults for required fields if missing
        if not normalized.get('timestamp'):
            normalized['timestamp'] = datetime.utcnow().isoformat()
        
        if not normalized.get('source'):
            normalized['source'] = f"unknown:{source_type}"
        
        return normalized
    
    def _parse_syslog(self, log_line: str) -> Dict:
        """Parse a syslog message into a dictionary."""
        # This is a simplified parser - in production, you'd want a more robust solution
        pattern = r'^<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
        match = re.match(pattern, log_line)
        if match:
            return match.groupdict()
        return {'message': log_line}
    
    def _parse_timestamp(self, timestamp: Any) -> str:
        """Parse various timestamp formats to ISO 8601."""
        if isinstance(timestamp, (int, float)):
            # Assume it's a Unix timestamp
            return datetime.fromtimestamp(timestamp).isoformat()
        elif isinstance(timestamp, str):
            # Try to parse common timestamp formats
            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%d %H:%M:%S',
                '%b %d %H:%M:%S',  # Syslog format
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%d %H:%M:%S.%f'
            ]:
                try:
                    dt = datetime.strptime(timestamp.split('.')[0], fmt)
                    return dt.isoformat()
                except (ValueError, AttributeError):
                    continue
        return datetime.utcnow().isoformat()
    
    def _normalize_severity(self, severity: Any) -> str:
        """Normalize log severity levels."""
        if isinstance(severity, int):
            # Syslog severity levels (0-7)
            levels = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
            return levels[min(max(0, severity), len(levels)-1)]
        
        severity = str(severity).lower()
        if severity in ['emerg', 'emergency', 'panic', 'fatal']:
            return 'emerg'
        elif severity in ['alert']:
            return 'alert'
        elif severity in ['crit', 'critical']:
            return 'crit'
        elif severity in ['err', 'error']:
            return 'err'
        elif severity in ['warn', 'warning']:
            return 'warning'
        elif severity in ['notice']:
            return 'notice'
        elif severity in ['info', 'information']:
            return 'info'
        elif severity in ['debug']:
            return 'debug'
        return 'info'
    
    def _map_windows_event_type(self, event_type: Any) -> str:
        """Map Windows Event types to standard types."""
        event_type = str(event_type).lower()
        if 'error' in event_type:
            return 'error'
        elif 'warning' in event_type:
            return 'warning'
        elif 'success' in event_type or 'audit_success' in event_type:
            return 'success'
        elif 'failure' in event_type or 'audit_failure' in event_type:
            return 'failure'
        return 'info'
    
    def _map_windows_severity(self, level: Any) -> str:
        """Map Windows Event levels to standard severity levels."""
        try:
            level = int(level)
            if level <= 1:  # Critical
                return 'crit'
            elif level <= 2:  # Error
                return 'err'
            elif level <= 3:  # Warning
                return 'warning'
            elif level <= 4:  # Information
                return 'info'
            else:  # Verbose
                return 'debug'
        except (ValueError, TypeError):
            return 'info'


class LogSource:
    """Base class for log sources."""
    
    def __init__(self, source_id: str, source_type: str, config: Optional[Dict] = None):
        """
        Initialize a log source.
        
        Args:
            source_id: Unique identifier for the source
            source_type: Type of log source (e.g., 'file', 'syslog', 'api')
            config: Configuration dictionary for the source
        """
        self.source_id = source_id
        self.source_type = source_type
        self.config = config or {}
        self.running = False
        self.callbacks = []
    
    def add_callback(self, callback: Callable[[Dict], None]) -> None:
        """Add a callback function to be called with new log entries."""
        if callable(callback):
            self.callbacks.append(callback)
    
    def start(self) -> None:
        """Start collecting logs from this source."""
        self.running = True
        logger.info(f"Started log source: {self.source_id} ({self.source_type})")
    
    def stop(self) -> None:
        """Stop collecting logs from this source."""
        self.running = False
        logger.info(f"Stopped log source: {self.source_id}")
    
    def _notify_callbacks(self, log_entry: Dict) -> None:
        """Notify all registered callbacks with a new log entry."""
        for callback in self.callbacks:
            try:
                callback(log_entry)
            except Exception as e:
                logger.error(f"Error in log callback: {e}")


class FileLogSource(LogSource):
    """Log source that reads from files."""
    
    def __init__(self, source_id: str, file_path: str, **kwargs):
        """
        Initialize a file log source.
        
        Args:
            source_id: Unique identifier for the source
            file_path: Path to the log file
            **kwargs: Additional arguments for LogSource
        """
        super().__init__(source_id, 'file', kwargs.get('config', {}))
        self.file_path = file_path
        self.position = 0
        self.watch = kwargs.get('watch', True)
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.observer = None
        self.handler = None
    
    def start(self) -> None:
        """Start watching the log file for changes."""
        super().start()
        
        # Read existing content if needed
        if self.config.get('read_existing', False):
            self._read_file()
        
        # Set up file watcher
        if self.watch:
            self.handler = FileChangeHandler(self)
            self.observer = Observer()
            self.observer.schedule(
                self.handler,
                os.path.dirname(os.path.abspath(self.file_path)),
                recursive=False
            )
            self.observer.start()
    
    def stop(self) -> None:
        """Stop watching the log file."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        super().stop()
    
    def _read_file(self) -> None:
        """Read new content from the file."""
        try:
            with open(self.file_path, 'r', encoding=self.encoding, errors='replace') as f:
                # Seek to the last read position
                if self.position > 0:
                    f.seek(self.position)
                
                # Read new lines
                for line in f:
                    self._process_line(line.strip())
                
                # Update the position
                self.position = f.tell()
        except FileNotFoundError:
            logger.warning(f"Log file not found: {self.file_path}")
        except Exception as e:
            logger.error(f"Error reading log file {self.file_path}: {e}")
    
    def _process_line(self, line: str) -> None:
        """Process a single log line."""
        if not line.strip():
            return
        
        # Create a log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source': f"file:{self.source_id}",
            'message': line,
            'file': self.file_path,
            'raw': line
        }
        
        # Notify callbacks
        self._notify_callbacks(log_entry)


class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events for log files."""
    
    def __init__(self, log_source: FileLogSource):
        """
        Initialize the file change handler.
        
        Args:
            log_source: The FileLogSource instance to notify of changes
        """
        self.log_source = log_source
    
    def on_modified(self, event):
        """Called when a file is modified."""
        if not event.is_directory and os.path.basename(event.src_path) == os.path.basename(self.log_source.file_path):
            self.log_source._read_file()


class LogCollector:
    """Manages multiple log sources and normalizes their output with enhanced features."""
    
    def __init__(self, normalizer: Optional[LogNormalizer] = None, config: Optional[Dict] = None):
        """Initialize the log collector with configuration.
        
        Args:
            normalizer: Optional LogNormalizer instance
            config: Configuration dictionary with log collector settings
        """
        self.normalizer = normalizer or LogNormalizer()
        self.sources: Dict[str, LogSource] = {}
        self.callbacks = []
        self.config = config or {}
        self._setup_logging()
        self._shutdown_event = Event()
        self._lock = Lock()
        self._stats = {
            'processed': 0,
            'errors': 0,
            'last_error': None,
            'start_time': datetime.utcnow().isoformat(),
        }
        
        # Thread pool for parallel processing
        max_workers = self.config.get('max_workers', 5)
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='log_collector_worker_'
        )
        
        # Queue for log entries
        self.queue = Queue(maxsize=self.config.get('queue_size', 10000))
        
        # Start processor thread
        self.processor_thread = Thread(
            target=self._process_queue,
            name='log_processor',
            daemon=True
        )
        self.processor_thread.start()
        
        logger.info(f"LogCollector initialized with {max_workers} workers")
    
    def add_source(self, source: LogSource) -> None:
        """
        Add a log source to the collector.
        
        Args:
            source: LogSource instance to add
        """
        if source.source_id in self.sources:
            raise ValueError(f"Log source with ID {source.source_id} already exists")
        
        # Add our callback to the source
        source.add_callback(self._process_log_entry)
        self.sources[source.source_id] = source
    
    def remove_source(self, source_id: str) -> None:
        """
        Remove a log source from the collector.
        
        Args:
            source_id: ID of the source to remove
        """
        if source_id in self.sources:
            self.sources[source_id].stop()
            del self.sources[source_id]
    
    def add_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Add a callback to be called with normalized log entries.
        
        Args:
            callback: Function that takes a log entry dictionary
        """
        if callable(callback):
            self.callbacks.append(callback)
    
    def start(self) -> None:
        """Start all log sources."""
        for source in self.sources.values():
            try:
                source.start()
            except Exception as e:
                logger.error(f"Error starting log source {source.source_id}: {e}")
    
    def stop(self) -> None:
        """Stop all log sources."""
        for source in self.sources.values():
            try:
                source.stop()
            except Exception as e:
                logger.error(f"Error stopping log source {source.source_id}: {e}")
    
    def _process_log_entry(self, log_entry: Dict) -> None:
        """Process a raw log entry through the normalizer and call callbacks.
        
        Args:
            log_entry: Raw log entry dictionary
        """
        try:
            # Add metadata
            log_entry.setdefault('@timestamp', datetime.utcnow().isoformat())
            log_entry.setdefault('@version', '1')
            
            # Add host information if not present
            if 'host' not in log_entry:
                log_entry['host'] = {
                    'name': socket.gethostname(),
                    'ip': socket.gethostbyname(socket.gethostname())
                }
            
            # Normalize the log entry
            normalized = self.normalizer.normalize(log_entry)
            
            # Add to queue for async processing with retry logic
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Check memory usage before adding to queue
                    if self._get_memory_usage() > 0.9:  # 90% of max memory
                        logger.warning("High memory usage, dropping log entry")
                        with self._lock:
                            self._stats['memory_drops'] = self._stats.get('memory_drops', 0) + 1
                        return
                        
                    self.queue.put(normalized, block=True, timeout=1.0)
                    with self._lock:
                        self._stats['processed'] += 1
                    break
                        
                except Full:
                    if attempt == max_retries - 1:
                        logger.warning("Log queue is full after retries, dropping log entry")
                        with self._lock:
                            self._stats['queue_full_drops'] = self._stats.get('queue_full_drops', 0) + 1
                    else:
                        time.sleep(0.5 * (attempt + 1))  # Exponential backoff
            
        except Exception as e:
            error_msg = f"Error processing log entry: {str(e)}"
            logger.error(error_msg, exc_info=True)
            with self._lock:
                self._stats['errors'] += 1
                self._stats['last_error'] = {
                    'message': error_msg,
                    'timestamp': datetime.utcnow().isoformat(),
                    'log_entry': str(log_entry)[:500]  # Truncate to avoid huge error logs
                }
                
            # Re-raise critical errors
            if isinstance(e, (MemoryError, RuntimeError)):
                raise
    
    def _get_memory_usage(self) -> float:
        """Get current process memory usage as a percentage of total available memory.
        
        Returns:
            float: Memory usage as a percentage (0.0 to 1.0)
        """
        try:
            import psutil
            process = psutil.Process()
            return process.memory_percent() / 100.0
        except ImportError:
            # Fallback if psutil is not available
            return 0.0
    
    def _process_queue(self) -> None:
        """Process the log entry queue."""
        while not self._shutdown_event.is_set():
            try:
                log_entry = self.queue.get(timeout=1.0)
                self._process_log_entry(log_entry)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing log queue: {e}", exc_info=True)
    
    def _setup_logging(self) -> None:
        """Configure logging for the log collector with enhanced features.
        
        Configures both console and file logging with rotation and compression.
        """
        logging_config = self.config.get('logging', {})
        if not logging_config.get('enabled', True):
            return

        # Set log level from config or default to INFO
        log_level = getattr(logging, logging_config.get('level', 'INFO').upper())
        log_file = logging_config.get('file')
        
        # Enhanced log format with process/thread info
        log_format = (
            '%(asctime)s | %(process)d:%(thread)d | %(levelname)-8s | '
            '%(name)s | %(filename)s:%(lineno)d - %(message)s'
        )
        
        # Create formatter with microsecond precision
        formatter = logging.Formatter(
            log_format,
            datefmt='%Y-%m-%d %H:%M:%S.%f',
            style='%'
        )

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)

        # Remove existing handlers to avoid duplicate logs
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Add console handler with color support if available
        try:
            import colorlog
            console_handler = colorlog.StreamHandler()
            color_formatter = colorlog.ColoredFormatter(
                '%(log_color)s' + log_format,
                datefmt='%Y-%m-%d %H:%M:%S.%f',
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white',
                }
            )
            console_handler.setFormatter(color_formatter)
        except ImportError:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            
        root_logger.addHandler(console_handler)

        # Add file handler if log file is specified
        if log_file:
            # Ensure log directory exists
            log_dir = os.path.dirname(os.path.abspath(log_file))
            os.makedirs(log_dir, exist_ok=True)
            
            # Use WatchedFileHandler if available for log rotation with external tools
            try:
                from logging.handlers import WatchedFileHandler
                file_handler = WatchedFileHandler(log_file, mode='a', encoding='utf-8')
            except ImportError:
                file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            
            # Set up log rotation with compression
            max_size = logging_config.get('max_size_mb', 100) * 1024 * 1024  # MB to bytes
            backup_count = logging_config.get('backup_count', 5)
            
            try:
                from logging.handlers import RotatingFileHandler
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=max_size,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
                
                # Compress old log files
                def namer(name):
                    return name + ".gz"
                    
                def rotator(source, dest):
                    import gzip
                    with open(source, 'rb') as f_in:
                        with gzip.open(dest, 'wb') as f_out:
                            f_out.writelines(f_in)
                    os.remove(source)
                
                file_handler.namer = namer
                file_handler.rotator = rotator
                
            except ImportError:
                logger.warning("RotatingFileHandler not available, using basic file handler")
            
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)
            
            # Log startup message with configuration
            logger.info("Logging initialized")
            logger.debug("Logging configuration: %s", logging_config)


def _setup_rotating_logs(log_file: str, max_size_mb: int = 100, backup_count: int = 5) -> None:
    """Configure rotating file handler for logs.
    
    Args:
        log_file: Path to the log file
        max_size_mb: Maximum size in MB before rotation
        backup_count: Number of backup files to keep
    """
    # Convert MB to bytes
    max_bytes = max_size_mb * 1024 * 1024
    
    # Create directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Configure rotating file handler
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    # Set formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S %Z'
    )
    file_handler.setFormatter(formatter)
    
    # Add to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    
    # Compress old log files
    def namer(name: str) -> str:
        return name + ".gz"
    
    def rotator(source: str, dest: str) -> None:
        with open(source, 'rb') as f_in:
            with gzip.open(dest, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)
    
    file_handler.namer = namer
    file_handler.rotator = rotator


def validate_config(config: Dict) -> Tuple[bool, List[str]]:
    """Validate the SIEM configuration.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    
    # Required top-level sections
    required_sections = ['log_collection', 'correlation', 'alerting']
    for section in required_sections:
        if section not in config:
            errors.append(f"Missing required section: {section}")
    
    # Validate log collection settings
    if 'log_collection' in config:
        log_cfg = config['log_collection']
        if not isinstance(log_cfg, dict):
            errors.append("log_collection must be a dictionary")
        else:
            if 'sources' in log_cfg and not isinstance(log_cfg['sources'], list):
                errors.append("log_collection.sources must be a list")
    
    # Validate correlation settings
    if 'correlation' in config:
        corr_cfg = config['correlation']
        if not isinstance(corr_cfg, dict):
            errors.append("correlation must be a dictionary")
        else:
            if 'rules_path' in corr_cfg and not os.path.isdir(corr_cfg['rules_path']):
                errors.append(f"Rules directory does not exist: {corr_cfg['rules_path']}")
    
    # Validate alerting settings
    if 'alerting' in config:
        alert_cfg = config['alerting']
        if not isinstance(alert_cfg, dict):
            errors.append("alerting must be a dictionary")
        else:
            if alert_cfg.get('enabled', False):
                if 'providers' not in alert_cfg or not alert_cfg['providers']:
                    errors.append("No alert providers configured but alerting is enabled")
    
    return len(errors) == 0, errors

def create_log_collector(config_path: Optional[str] = None) -> 'LogCollector':
    """
    Create and configure a LogCollector instance from a configuration file.
    
    Args:
        config_path: Path to the configuration file (YAML or JSON).
                   If None, uses default configuration.
        
    Returns:
        Configured LogCollector instance
        
    Raises:
        ValueError: If configuration is invalid
        FileNotFoundError: If config file is not found
        yaml.YAMLError: If YAML parsing fails
        json.JSONDecodeError: If JSON parsing fails
        PermissionError: If log file cannot be written to
    """
    # Default configuration
    default_config = {
        'normalizer': {},
        'sources': [],
        'max_workers': 5,
        'queue_size': 10000,
        'logging': {
            'enabled': True,
            'file': 'siem_collector.log',
            'max_size_mb': 100,
            'backup_count': 5,
            'level': 'INFO',
            'compress': True
        },
        'rate_limiting': {
            'enabled': True,
            'max_events_per_second': 1000,
            'burst_capacity': 5000
        },
        'security': {
            'sensitive_data_redaction': True,
            'max_log_size': 10485760,  # 10MB
            'allowed_log_sources': ['file', 'syslog', 'api']
        }
    }
        
    # If no config path provided, use default config
    if config_path is None:
        config = default_config
    else:
        try:
            # Resolve config path
            config_path = Path(config_path).resolve()
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            # Load and parse config file
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.suffix.lower() == '.json':
                    file_config = json.load(f)
                else:  # Assume YAML
                    file_config = yaml.safe_load(f) or {}
            
            # Deep merge with default config
            config = deep_merge(default_config, file_config)
            
            # Validate configuration
            is_valid, validation_errors = validate_config(config)
            if not is_valid:
                error_msg = "Invalid configuration:\n" + "\n".join(f"- {e}" for e in validation_errors)
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Ensure log directory is writable if logging to file
            if config.get('logging', {}).get('enabled', True):
                log_file = config['logging'].get('file')
                if log_file:
                    log_dir = os.path.dirname(os.path.abspath(log_file))
                    os.makedirs(log_dir, exist_ok=True)
                    # Test file creation
                    try:
                        with open(log_file, 'a'):
                            pass
                    except (IOError, OSError) as e:
                        raise PermissionError(f"Cannot write to log file {log_file}: {e}")
            
            logger.info(f"Successfully loaded configuration from {config_path}")
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in config file: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in config file: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    # Create and configure the collector
    try:
        collector = LogCollector(
            normalizer=LogNormalizer(config.get('normalizer', {})),
            config=config
        )
        
        # Configure log sources
        for source_config in config.get('sources', []):
            try:
                source_type = source_config.get('type')
                source_id = source_config.get('id')
                
                if not source_type or not source_id:
                    logger.warning("Skipping source with missing type or id")
                    continue
                
                if source_type == 'file':
                    file_path = source_config.get('path')
                    if not file_path:
                        logger.warning(f"Missing path for file source {source_id}")
                        continue
                    
                    # Validate file exists and is readable
                    if not os.path.isfile(file_path):
                        logger.warning(f"Log file does not exist: {file_path}")
                        if not source_config.get('create_if_missing', False):
                            continue
                        # Create empty file if configured to do so
                        try:
                            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                            Path(file_path).touch()
                        except Exception as e:
                            logger.error(f"Failed to create log file {file_path}: {e}")
                            continue
                    
                    # Check file permissions
                    if not os.access(file_path, os.R_OK):
                        logger.error(f"Insufficient permissions to read log file: {file_path}")
                        continue
                    
                    # Create and add the file source
                    source = FileLogSource(
                        source_id=source_id,
                        file_path=file_path,
                        watch=source_config.get('watch', True),
                        encoding=source_config.get('encoding', 'utf-8'),
                        config={
                            'read_existing': source_config.get('read_existing', False),
                            'follow': source_config.get('follow', True)
                        }
                    )
                    collector.add_source(source)
                    logger.info(f"Added file log source: {source_id} ({file_path})")
                
                # Add support for other source types here (syslog, API, etc.)
                elif source_type == 'syslog':
                    # TODO: Implement syslog source
                    logger.warning("Syslog source type not yet implemented")
                else:
                    logger.warning(f"Unsupported source type: {source_type}")
                
            except Exception as e:
                logger.error(f"Error configuring log source {source_id}: {e}", exc_info=True)
        
        return collector
        
    except Exception as e:
        logger.critical(f"Failed to initialize LogCollector: {e}", exc_info=True)
        raise
    
    return collector


# Example usage
if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a simple log collector
    collector = LogCollector()
    
    # Add a file source
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        source = FileLogSource(
            source_id="test_file",
            file_path=file_path,
            watch=True,
            config={'read_existing': True}
        )
        collector.add_source(source)
    
    # Add a callback to print normalized logs
    def print_log(entry):
        print(f"[{entry.get('severity', 'info').upper()}] {entry.get('timestamp')} - {entry.get('source')} - {entry.get('message')}")
    
    collector.add_callback(print_log)
    
    # Start collecting logs
    try:
        print("Starting log collector. Press Ctrl+C to stop.")
        collector.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping log collector...")
        collector.stop()
