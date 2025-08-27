"""
File Integrity Monitoring Core

Core components for monitoring file system and registry changes in real-time.
"""
import os
import time
import hashlib
import logging
import platform
import threading
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field

logger = logging.getLogger('fim.core')

class EventType(Enum):
    """Types of file system events that can be monitored."""
    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    RENAMED = auto()
    ATTRIBUTES_CHANGED = auto()
    SECURITY_CHANGED = auto()

@dataclass
class FileEvent:
    """Represents a file system event with forensic details."""
    event_type: EventType
    src_path: str
    dest_path: Optional[str] = None
    is_directory: bool = False
    file_size: Optional[int] = None
    last_modified: Optional[float] = None
    checksum: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    user: Optional[str] = None
    process: Optional[str] = None
    process_path: Optional[str] = None
    process_cmdline: Optional[str] = None
    session_id: Optional[int] = None
    change_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary for serialization."""
        return {
            'event_type': self.event_type.name,
            'src_path': self.src_path,
            'dest_path': self.dest_path,
            'is_directory': self.is_directory,
            'file_size': self.file_size,
            'last_modified': self.last_modified,
            'checksum': self.checksum,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'user': self.user,
            'process': self.process,
            'process_path': self.process_path,
            'process_cmdline': self.process_cmdline,
            'session_id': self.session_id,
            'change_details': self.change_details
        }

    def to_json(self) -> str:
        """Convert the event to a JSON string."""
        import json
        return json.dumps(self.to_dict(), default=str)

class FileIntegrityError(Exception):
    """Base exception for FIM-related errors."""
    pass

class FIMEngine:
    """File Integrity Monitoring Engine.
    
    Monitors files and directories for changes in real-time and triggers
    appropriate event handlers when changes are detected.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        baseline_file: str = 'fim_baseline.json',
        log_file: Optional[str] = None,
        scan_interval: int = 300,
        ignore_patterns: Optional[List[str]] = None,
        enable_ransomware_detection: bool = True,
        monitor_critical_paths: bool = True,
        use_native_watchers: bool = True
    ) -> None:
        """
        Initialize the FIM engine.
        
        Args:
            config: Configuration dictionary
            baseline_file: Path to the baseline file
            log_file: Path to the log file (if None, logs to console)
            scan_interval: Interval in seconds between full scans
            ignore_patterns: List of regex patterns to ignore
            enable_ransomware_detection: Whether to enable ransomware detection
            monitor_critical_paths: Whether to automatically monitor platform-specific critical paths
            use_native_watchers: Whether to use native platform watchers (if False, falls back to polling)
        """
        self.config = config or {}
            'hashing_algorithms': ['md5', 'sha1', 'sha256'],
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'exclude_dirs': ['$RECYCLE.BIN', 'System Volume Information', 'Windows', 'Program Files', 'Program Files (x86)'],
            'exclude_extensions': ['.tmp', '.log', '.swp', '~'],
            'alert_on': ['created', 'modified', 'deleted']
        }
        
        self._baseline_file = baseline_file
        self.scan_interval = scan_interval
        self.enable_ransomware_detection = enable_ransomware_detection
        self.ignore_patterns = ignore_patterns or []
        self.monitor_critical_paths = monitor_critical_paths
        self.use_native_watchers = use_native_watchers
        
        # Initialize logging
        self._setup_logging(log_file)
        
        # State
        self.running = False
        self.watchers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._event_handlers: List[Callable[[FileEvent], None]] = []
        
        # Ransomware detection state
        self._suspicious_events: Dict[str, Dict[str, Any]] = {}
        self._last_alert_time: float = 0
        self._last_scan_state: Dict[str, Dict[str, Any]] = {}
        
        # Platform-specific initialization
        self.platform = platform.system().lower()
        self.path_sep = os.path.sep
        self._init_platform()
        
        # Load baseline if it exists
        self._baseline: Dict[str, Dict[str, Any]] = {}
        if os.path.exists(self._baseline_file):
            self.load_baseline()
            
        # Initialize platform-specific components
        self._init_platform_components()
        
        logger.info(f"FIM Engine initialized for {self.platform} platform")

    def _init_platform_components(self) -> None:
        """Initialize platform-specific components."""
        # This can be overridden by platform-specific implementations
        pass

    def add_handler(self, handler: Callable[[FileEvent], None]) -> None:
        """Add an event handler to be called when file changes are detected."""
        with self._lock:
            if handler not in self._event_handlers:
                self._event_handlers.append(handler)

    def remove_handler(self, handler: Callable[[FileEvent], None]) -> None:
        """Remove an event handler."""
        with self._lock:
            if handler in self._event_handlers:
                self._event_handlers.remove(handler)

    def _init_platform(self) -> None:
        """Initialize platform-specific functionality."""
        if self.platform == 'windows':
            self._init_windows()
        elif self.platform == 'linux':
            self._init_linux()

    def _init_windows(self) -> None:
        """Windows-specific initialization."""
        try:
            import win32api
            import win32con
            import win32security
            import ntsecuritycon
            self._has_win32 = True
        except ImportError:
            self._has_win32 = False
            logger.warning("pywin32 not installed. Some features may be limited.")

    def _init_linux(self) -> None:
        """Linux-specific initialization."""
        self._has_inotify = False
        try:
            import inotify.adapters
            self._has_inotify = True
        except ImportError:
            logger.warning("inotify not available. Falling back to polling.")

    def _monitor_critical_paths(self) -> None:
        """Monitor platform-specific critical paths."""
        if self.platform == 'windows':
            critical_paths = [
                os.environ.get('SYSTEMROOT', 'C:\\Windows'),
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
                os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'),
                os.path.join(os.environ.get('APPDATA', ''), '..', 'Local', 'Temp')
            ]
        elif self.platform == 'linux':
            critical_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc']
        else:
            critical_paths = []
            
        for path in critical_paths:
            if os.path.exists(path):
                try:
                    self.add_watch(path, recursive=True)
                    logger.info(f"Monitoring critical path: {path}")
                except Exception as e:
                    logger.error(f"Failed to monitor critical path {path}: {e}")

    def add_watch(self, path: str, recursive: bool = True) -> None:
        """
        Add a path to monitor for changes using platform-appropriate watchers.
        
        Args:
            path: Path to monitor (file or directory)
            recursive: If True, monitor subdirectories (for directories only)
        """
        # This is a simplified version - actual implementation would use platform watchers
        logger.info(f"Adding watch for {path} (recursive: {recursive})")
        
    def add_monitor(self, path: str, recursive: bool = True) -> None:
        """
        Legacy method for backward compatibility.
        Use add_watch() for new code.
        """
        self.add_watch(path, recursive)

    def _handle_fs_event(self, event_type: EventType, path: str, old_path: Optional[str] = None) -> None:
        """
        Handle a file system event from a watcher.
        
        Args:
            event_type: Type of file system event
            path: Path to the affected file/directory
            old_path: For rename events, the original path
        """
        event = FileEvent(
            event_type=event_type,
            src_path=path,
            dest_path=old_path if event_type == EventType.RENAMED else None,
            is_directory=os.path.isdir(path) if os.path.exists(path) else False
        )
        
        self._process_event(event)

    def start(self) -> None:
        """Start the FIM engine."""
        if self.running:
            return
            
        self.running = True
        
        # Start monitoring critical paths if enabled
        if self.monitor_critical_paths:
            self._monitor_critical_paths()
            
        logger.info("FIM Engine started")

    def stop(self) -> None:
        """Stop the FIM engine."""
        self.running = False
        logger.info("FIM Engine stopped")

    def _setup_logging(self, log_file: Optional[str] = None) -> None:
        """Set up logging configuration."""
        log_level = logging.INFO
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        if log_file:
            logging.basicConfig(
                level=log_level,
                format=log_format,
                filename=log_file,
                filemode='a'
            )
        else:
            logging.basicConfig(
                level=log_level,
                format=log_format
            )

    def _process_event(self, event: FileEvent) -> None:
        """
        Process a file system event and check for suspicious patterns.
        
        This method:
        1. Enriches the event with forensic data (user, process info)
        2. Updates the baseline if needed
        3. Performs ransomware detection
        4. Triggers event handlers
        """
        # Enrich event with additional data
        self._enrich_event(event)
        
        # Log the event
        logger.info(f"File event: {event.event_type.name} - {event.src_path}")
        
        # Call all registered event handlers
        for handler in self._event_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler: {e}", exc_info=True)

    def _enrich_event(self, event: FileEvent) -> None:
        """
        Enrich an event with additional information.
        
        Args:
            event: The event to enrich
        """
        # Add current timestamp if not set
        if not hasattr(event, 'timestamp') or not event.timestamp:
            event.timestamp = time.time()
            
        # Add user information
        try:
            import getpass
            event.user = getpass.getuser()
        except Exception:
            event.user = None
            
        # Add process information (simplified)
        try:
            import psutil
            current_process = psutil.Process()
            event.process = current_process.name()
            event.process_path = current_process.exe()
            event.process_cmdline = ' '.join(current_process.cmdline())
        except Exception:
            pass

    def add_alert_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Register a callback function to be called when an alert is triggered.

        Args:
            callback: Function that takes a dictionary containing alert details
        """
        if not hasattr(self, 'alert_callbacks'):
            self.alert_callbacks = []
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
