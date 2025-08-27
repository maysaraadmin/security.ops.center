"""
File Integrity Monitoring Core

Core components for monitoring file system and registry changes in real-time.
"""
import os
import hashlib
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any, Union
from pathlib import Path
import time
import json
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    """Represents a file system event with forensic details.
    
    Attributes:
        event_type: Type of file system event
        src_path: Source path of the file/directory
        dest_path: Destination path (for rename events)
        is_directory: Whether the path is a directory
        file_size: Size of the file in bytes
        last_modified: Last modified timestamp
        checksum: File checksum (for backward compatibility)
        metadata: Additional file metadata
        timestamp: When the event occurred
        user: User who triggered the event (username or SID)
        process: Process that triggered the event (name or PID)
        process_path: Full path to the process executable
        process_cmdline: Command line arguments of the process
        session_id: Terminal session ID where the change occurred
        change_details: Dictionary of what changed (old vs new values)
    """
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
        result = {
            'event_type': self.event_type.name,
            'src_path': self.src_path,
            'dest_path': self.dest_path,
            'is_directory': self.is_directory,
            'file_size': self.file_size,
            'last_modified': self.last_modified,
            'checksum': self.checksum,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).isoformat(),
            'user': self.user,
            'process': self.process,
            'process_path': self.process_path,
            'process_cmdline': self.process_cmdline,
            'session_id': self.session_id,
            'change_details': self.change_details
        }
        # Remove None values for cleaner output
        return {k: v for k, v in result.items() if v is not None}
    
    def to_json(self) -> str:
        """Convert the event to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

class FileIntegrityError(Exception):
    """Base exception for FIM-related errors."""
    pass

class FIMEngine:
    """
    File Integrity Monitoring Engine.
    
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
        # Add critical paths to monitor if enabled
        if self.monitor_critical_paths:
            self._monitor_critical_paths()
            
        # Log platform capabilities
        if self.platform == 'windows':
            logger.info(f"Windows platform: pywin32 available: {getattr(self, '_has_win32', False)}")
        elif self.platform == 'linux':
            logger.info(f"Linux platform: inotify available: {getattr(self, '_has_inotify', False)}")
        
        if not self.use_native_watchers:
            logger.info("Native watchers disabled, using polling mode")
        
        # Ransomware detection
        self._ransomware_detection = self.config.get('enable_ransomware_detection', True)
        if self.enable_ransomware_detection:
            from .ransomware_detector import RansomwareDetector
            self.ransomware_detector = RansomwareDetector(self.config.get('ransomware_config'))
        
        # Hashing configuration
        self.hash_algorithms = self.config.get('hash_algorithms', ['sha256'])
        if isinstance(self.hash_algorithms, str):
            self.hash_algorithms = [self.hash_algorithms]
        
        # Validate hash algorithms
        self.valid_algorithms = set(hashlib.algorithms_available)
        for algo in self.hash_algorithms:
            if algo not in self.valid_algorithms:
                logger.warning(f"Unsupported hash algorithm: {algo}. Defaulting to 'sha256'.")
                self.hash_algorithms = ['sha256']
                break
        
        logger.info(f"FIM Engine initialized with hash algorithms: {', '.join(self.hash_algorithms)}")
        
        # For backward compatibility
        self.hash_algorithm = self.hash_algorithms[0]  # Default to first algorithm
        
        # Platform-specific initialization
        self._init_platform()
        
        # Monitor critical system paths if enabled
        if self.config.get('monitor_critical_paths', True):
            self._monitor_critical_paths()
    
    def add_handler(self, handler: Callable[[FileEvent], None]) -> None:
        """Add an event handler to be called when file changes are detected."""
        self._event_handlers.append(handler)
        logger.debug(f"Added event handler: {handler.__class__.__name__}")
    
    def remove_handler(self, handler: Callable[[FileEvent], None]) -> None:
        """Remove an event handler."""
        if handler in self.callbacks:
            self.callbacks.remove(handler)
            logger.debug(f"Removed event handler: {handler.__class__.__name__}")
    
    def _init_platform(self) -> None:
        """Initialize platform-specific functionality."""
        self.platform = platform.system().lower()
        logger.info(f"Initializing FIM engine for platform: {self.platform}")
        
        # Platform-specific initialization can go here
        if self.platform == 'windows':
            # Windows-specific initialization
            self.path_sep = '\\'
            self._init_windows()
        elif self.platform == 'linux':
            # Linux-specific initialization
            self.path_sep = '/'
            self._init_linux()
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
            self.path_sep = os.path.sep
    
    def _init_windows(self) -> None:
        """Windows-specific initialization."""
        # Import Windows-specific modules
        try:
            import win32security
            import win32api
            self._has_win32 = True
        except ImportError:
            self._has_win32 = False
            logger.warning("pywin32 not available, some Windows-specific features may be limited")
    
    def _init_linux(self) -> None:
        """Linux-specific initialization."""
        # Check for inotify support
        try:
            import ctypes
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            self._has_inotify = hasattr(libc, 'inotify_init')
            if not self._has_inotify:
                logger.warning("inotify not available, falling back to polling")
        except Exception as e:
            logger.warning(f"Could not check for inotify support: {e}")
            self._has_inotify = False
    
    def _monitor_critical_paths(self) -> None:
        """Monitor platform-specific critical paths."""
        critical_paths = get_critical_paths()
        for path in critical_paths:
            try:
                self.add_watch(path, recursive=True)
                logger.info(f"Added critical path to monitoring: {path}")
            except Exception as e:
                logger.warning(f"Failed to monitor critical path {path}: {e}")
    
    def add_watch(self, path: str, recursive: bool = True) -> None:
        """
        Add a path to monitor for changes using platform-appropriate watchers.
        
        Args:
            path: Path to monitor (file or directory)
            recursive: If True, monitor subdirectories (for directories only)
        """
        path = os.path.normpath(path)
        
        # Skip if already being monitored
        if path in self.watchers:
            logger.debug(f"Already watching: {path}")
            return
            
        try:
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                return
                
            # Create a watcher for this path
            watcher = get_platform_watcher(
                path,
                callback=self._handle_fs_event,
                recursive=recursive
            )
            
            # Store the watcher
            self.watchers[path] = {
                'watcher': watcher,
                'recursive': recursive,
                'path': path
            }
            
            logger.info(f"Added watch for: {path} (recursive={recursive})")
            
            # Start the watcher if the engine is running
            if self.running:
                watcher.start()
                
        except Exception as e:
            logger.error(f"Failed to add watch for {path}: {e}", exc_info=True)
    
    def add_monitor(self, path: str, recursive: bool = True) -> None:
        """
        Legacy method for backward compatibility.
        Use add_watch() for new code.
        """
        import warnings
        warnings.warn(
            "add_monitor() is deprecated, use add_watch() instead",
            DeprecationWarning,
            stacklevel=2
        )
        self.add_watch(path, recursive)
    
    def _handle_fs_event(self, event_type: EventType, path: str, old_path: Optional[str] = None) -> None:
        """
        Handle a file system event from a watcher.
        
        Args:
            event_type: Type of file system event
            path: Path to the affected file/directory
            old_path: For rename events, the original path
        """
        try:
            # Skip if the path should be ignored
            if self._should_ignore(path):
                return
                
            # Get file metadata
            is_dir = os.path.isdir(path)
            file_size = os.path.getsize(path) if not is_dir and os.path.exists(path) else 0
            last_modified = os.path.getmtime(path) if os.path.exists(path) else time.time()
            
            # Get checksum for files (if not a directory and not deleted)
            checksum = None
            if not is_dir and event_type != EventType.DELETED and os.path.isfile(path):
                try:
                    checksum = self._calculate_checksum(path)
                except (IOError, OSError) as e:
                    logger.warning(f"Could not calculate checksum for {path}: {e}")
            
            # Create the event
            event = FileEvent(
                event_type=event_type,
                src_path=path,
                dest_path=old_path if event_type == EventType.RENAMED and old_path else None,
                is_directory=is_dir,
                file_size=file_size,
                last_modified=last_modified,
                checksum=checksum
            )
            
            # Enrich with process and user information
            self._enrich_event(event)
            
            # Process the event
            self._process_event(event)
            
        except Exception as e:
            logger.error(f"Error handling filesystem event for {path}: {e}", exc_info=True)
    
    def start(self) -> None:
        """Start the FIM engine."""
        if self.running:
            logger.warning("FIM engine is already running")
            return
            
        logger.info("Starting FIM engine...")
        self.running = True
        
        # Load baseline if it exists
        if os.path.exists(self._baseline_file):
            self.load_baseline()
        
        # Start all watchers
        for watcher_info in self.watchers.values():
            try:
                watcher_info['watcher'].start()
            except Exception as e:
                logger.error(f"Failed to start watcher for {watcher_info['path']}: {e}", exc_info=True)
        
        # Start the periodic scanner thread
        self._stop_scan = threading.Event()
        self._scanner_thread = threading.Thread(target=self._periodic_scan, daemon=True)
        self._scanner_thread.start()
        
        logger.info("FIM engine started")
    
    def stop(self) -> None:
        """Stop the FIM engine."""
        if not self.running:
            return
            
        self.running = False
        logger.info("Stopping FIM engine...")
        
        # Stop all watchers
        for watcher_info in self.watchers.values():
            try:
                watcher_info['watcher'].stop()
            except Exception as e:
                logger.error(f"Failed to stop watcher for {watcher_info['path']}: {e}", exc_info=True)
        
        # Stop the periodic scanner thread
        self._stop_scan.set()
        self._scanner_thread.join()
        
        logger.info("FIM engine stopped")
    
    def create_baseline(self, force: bool = False) -> bool:
        """
        Create or update the baseline of all monitored files.
        
        Args:
            force: If True, force creation of a new baseline even if one exists
            
        Returns:
            bool: True if baseline was created/updated, False otherwise
        """
        if not force and self._baseline_loaded:
            logger.info("Baseline already exists. Use force=True to recreate.")
            return False
            
        logger.info("Creating file integrity baseline...")
        start_time = time.time()
        self.baseline.clear()
        
        # Add all monitored paths to baseline
        for monitor in self.monitors.values():
            path = monitor.path
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                continue
                
            if os.path.isfile(path):
                self._add_file_to_baseline(path)
            elif os.path.isdir(path):
                recursive = getattr(monitor, 'recursive', True)
                self._scan_directory(path, recursive)
        
        # Save the baseline to disk if configured
        if self.config.get('baseline_file'):
            self.save_baseline()
            
        self._baseline_loaded = True
        elapsed = time.time() - start_time
        logger.info(f"Baseline created with {len(self.baseline)} items in {elapsed:.2f} seconds")
        return True
    
    def calculate_file_hashes(self, file_path: str, chunk_size: int = 65536) -> Dict[str, str]:
        """
        Calculate multiple hash values for a file using all configured algorithms.
        
        Args:
            file_path: Path to the file
            chunk_size: Size of chunks to read (default: 64KB)
            
        Returns:
            Dictionary mapping algorithm names to their hash values
        """
        if not os.path.isfile(file_path):
            return {}
            
        # Initialize hashers for all algorithms
        hashers = {algo: hashlib.new(algo) for algo in self.hash_algorithms}
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks and update all hashers
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)
                        
            # Return hex digests for all hashes
            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
            
        except (IOError, OSError) as e:
            logger.warning(f"Could not calculate hashes for {file_path}: {e}")
            return {}
    
    def _get_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Get metadata for a file or directory.
        
        Args:
            file_path: Path to the file or directory
            
        Returns:
            Dictionary containing file metadata including multiple hashes
        """
        try:
            stat = os.stat(file_path)
            
            # Get basic file metadata
            metadata = {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'ctime': stat.st_ctime,
                'mode': stat.st_mode,
                'uid': stat.st_uid,
                'gid': stat.st_gid,
                'inode': stat.st_ino,
                'device': stat.st_dev,
                'is_dir': os.path.isdir(file_path),
                'hashes': {}
            }
            
            # Calculate hashes for files (not directories)
            if not metadata['is_dir'] and metadata['size'] > 0:
                metadata['hashes'] = self.calculate_file_hashes(file_path)
                
            return metadata
            
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not get metadata for {file_path}: {e}")
            return None
    
    def _add_file_to_baseline(self, file_path: str) -> None:
        """
        Add a file or directory to the baseline.

        Args:
            file_path: Path to the file or directory to add
        """
        try:
            metadata = self._get_file_metadata(file_path)
            if metadata is not None:
                metadata['last_checked'] = time.time()
                self.baseline[file_path] = metadata
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not add {file_path} to baseline: {e}")
    
    def _scan_directory(self, directory: str, recursive: bool = True) -> None:
        """Scan a directory and add all files to the baseline."""
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                            
                        if entry.is_file():
                            self._add_file_to_baseline(entry.path)
                        elif entry.is_dir() and recursive:
                            self._scan_directory(entry.path, recursive)
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Error scanning {entry.path}: {e}")
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not scan directory {directory}: {e}")
    
    def _should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored based on include/exclude patterns."""
        path = os.path.normpath(path).replace('\\', '/')
        
        # Check exclude patterns
        for pattern in self.config.get('exclude_patterns', []):
            if Path(path).match(pattern):
                return True
        
        # Check include patterns
        if self.config.get('include_patterns', ['*']) != {'*'}:
            for pattern in self.config.get('include_patterns', ['*']):
                if Path(path).match(pattern):
                    return False
            return True  # Not in include patterns
            
        return False  # Not in exclude patterns and no specific includes
    
    def _calculate_checksum(self, file_path: str, algorithm: Optional[str] = None, 
                          chunk_size: int = 65536) -> str:
        """
        Calculate the checksum of a file using the specified algorithm.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use (default: first configured algorithm)
            chunk_size: Size of chunks to read (default: 64KB)
            
        Returns:
            Hex digest of the file's checksum, or empty string on error
        """
        if not os.path.isfile(file_path):
            return ""
            
        algo = algorithm or self.hash_algorithms[0]
        if algo not in self.valid_algorithms:
            logger.error(f"Unsupported hash algorithm: {algo}")
            return ""
            
        hasher = hashlib.new(algo)
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            logger.warning(f"Could not calculate checksum for {file_path}: {e}")
            return ""
    
    def _get_process_info(self, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Get information about the current or specified process.
        
        Args:
            pid: Process ID (None for current process)
            
        Returns:
            Dictionary with process information
        """
        try:
            import psutil
            import getpass
            
            process = psutil.Process(pid) if pid else psutil.Process()
            
            return {
                'pid': process.pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()),
                'username': process.username(),
                'create_time': process.create_time(),
                'terminal': getattr(process, 'terminal', lambda: None)()
            }
        except (ImportError, psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.debug(f"Could not get process info: {e}")
            return {}
    
    def _enrich_event(self, event: FileEvent) -> None:
        """
        Enrich an event with additional information.
        
        Args:
            event: The event to enrich
        """
        # Get the current process information
        try:
            process_info = get_process_info(os.getpid())
            if process_info:
                event.process = process_info.get('name', '')
                event.process_path = process_info.get('exe', '')
                event.process_cmdline = ' '.join(process_info.get('cmdline', []))
                event.user = process_info.get('username', '')
            
            # Get file owner if available
            if os.path.exists(event.src_path):
                owner = get_file_owner(event.src_path)
                if owner:
                    if 'metadata' not in event.metadata:
                        event.metadata['owner'] = {}
                    event.metadata['owner']['current'] = owner
            
            # Get session ID (platform-specific)
            if self.platform == 'windows':
                try:
                    import ctypes
                    from ctypes import wintypes
                    
                    kernel32 = ctypes.windll.kernel32
                    ProcessIdToSessionId = kernel32.ProcessIdToSessionId
                    ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
                    ProcessIdToSessionId.restype = wintypes.BOOL
                    
                    session_id = wintypes.DWORD()
                    if ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
                        event.session_id = session_id.value
                except Exception as e:
                    logger.debug(f"Could not get session ID: {e}")
            
            # Add platform-specific metadata
            if 'metadata' not in event.metadata:
                event.metadata['platform'] = {}
            event.metadata['platform']['name'] = self.platform
            event.metadata['platform']['node'] = platform.node()
            event.metadata['platform']['release'] = platform.release()
            event.metadata['platform']['version'] = platform.version()
            event.metadata['platform']['machine'] = platform.machine()
            
        except Exception as e:
            logger.debug(f"Error enriching event: {e}", exc_info=True)
    
    def _periodic_scan(self) -> None:
        """Periodically scan watched paths to detect changes that might have been missed."""
        logger.info("Starting periodic scanner thread")
        
        last_scan = {}
        
        while not self._stop_scan.is_set():
            try:
                current_time = time.time()
                
                # Scan each watched path
                for watcher_info in list(self.watchers.values()):
                    path = watcher_info['path']
                    recursive = watcher_info['recursive']
                    
                    # Skip if we scanned this path recently
                    if path in last_scan and (current_time - last_scan[path]) < self.scan_interval:
                        continue
                    
                    try:
                        self._scan_path(path, recursive)
                        last_scan[path] = current_time
                    except Exception as e:
                        logger.error(f"Error scanning {path}: {e}", exc_info=True)
                
                # Sleep until the next scan interval or until stopped
                self._stop_scan.wait(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in periodic scanner: {e}", exc_info=True)
                # Prevent tight loop on error
                time.sleep(5)
        
        logger.info("Periodic scanner thread stopped")
    
    def _scan_path(self, path: str, recursive: bool = True) -> None:
        """
        Scan a path and generate events for any changes since the last scan.
        
        Args:
            path: Path to scan (file or directory)
            recursive: If True, scan subdirectories
        """
        if not os.path.exists(path):
            logger.debug(f"Path does not exist, skipping scan: {path}")
            return
        
        # For files, just check the file itself
        if os.path.isfile(path):
            self._check_file_changes(path)
            return
        
        # For directories, walk the directory tree
        for root, dirs, files in os.walk(path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore(os.path.join(root, d))]
            
            # Check files in this directory
            for filename in files:
                filepath = os.path.join(root, filename)
                if not self._should_ignore(filepath):
                    self._check_file_changes(filepath)
            
            # If not recursive, don't process subdirectories
            if not recursive:
                break
    
    def _check_file_changes(self, filepath: str) -> None:
        """Check if a file has changed since the last scan and generate events if needed."""
        try:
            # Skip if the file should be ignored
            if self._should_ignore(filepath):
                return
            
            # Get current file stats
            try:
                stat = os.stat(filepath)
            except OSError as e:
                logger.debug(f"Could not stat {filepath}: {e}")
                return
            
            # Check if this is a new or modified file
            if filepath not in self._last_scan_state:
                # New file
                self._handle_fs_event(EventType.CREATED, filepath)
            else:
                # Check if modified
                last_modified = self._last_scan_state[filepath].get('mtime', 0)
                if stat.st_mtime > last_modified + 1.0:  # 1s threshold to avoid mtime precision issues
                    self._handle_fs_event(EventType.MODIFIED, filepath)
            
            # Update the last scan state
            self._last_scan_state[filepath] = {
                'mtime': stat.st_mtime,
                'size': stat.st_size,
                'inode': stat.st_ino
            }
            
        except Exception as e:
            logger.error(f"Error checking file changes for {filepath}: {e}", exc_info=True)
    
    def _should_ignore(self, path: str) -> bool:
        """
        Check if a path should be ignored based on ignore patterns.
        
        Args:
            path: Path to check
            
        Returns:
            bool: True if the path should be ignored, False otherwise
        """
        # Normalize path for comparison
        path = os.path.normpath(path).lower()
        
        # Skip hidden files and directories (Unix-style and Windows-style)
        path_parts = path.split(os.path.sep)
        if any(part.startswith('.') for part in path_parts):
            return True
            
        # Skip common temporary and system files/directories
        temp_patterns = [
            '~$',  # Office temp files
            '.tmp$',
            '.swp$',
            '\temp\\',
            '\tmp\\',
            '\\$recycle.bin\\',
            '\\system volume information\\',
            '\\pagefile.sys$',
            '\\hiberfil.sys$',
            '\\swapfile.sys$',
            '\\$extend\\$usnjrnl$',
            '\\$logfile$',
            '\\$mft$',
            '\\$secure$',
            '\\$volume',
            '\\$badclus$',
            '\\$boot',
            '\\$bitmap',
            '\\$upcase',
            '\\$extend',
            '\\$objid$',
            '\\$quota$',
            '\\$reparse$',
            '\\$txf_data$',
            '\\$extend\\$quota',
            '\\$extend\\$reparse',
            '\\$extend\\$objid',
            '\\$extend\\$usnjrnl',
            '\\$extend\\$secure',
            '\\$extend\\$upcase',
            '\\$extend\\$volume',
            '\\$extend\\$bitmap',
            '\\$extend\\$badclus',
            '\\$extend\\$logfile',
            '\\$extend\\$mft',
            '\\$extend\\$objid',
            '\\$extend\\$quota',
            '\\$extend\\$reparse',
            '\\$extend\\$secure',
            '\\$extend\\$upcase',
            '\\$extend\\$volume',
            '\\$extend\\$bitmap',
            '\\$extend\\$badclus',
            '\\$extend\\$logfile',
            '\\$extend\\$mft',
        ]
        
        if any(re.search(pattern, path, re.IGNORECASE) for pattern in temp_patterns):
            return True
            
        # Check against user-defined ignore patterns
        for pattern in self.ignore_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        return False
    
    def _process_event(self, event: FileEvent) -> None:
        """
        Process a file system event and check for suspicious patterns.
        
        This method:
        1. Enriches the event with forensic data (user, process info)
        2. Updates the baseline if needed
        3. Performs ransomware detection
        4. Triggers event handlers
        """
        try:
            # Enrich event with forensic data
            self._enrich_event_with_forensic_data(event)
            
            # Update baseline if needed
            if event.event_type == EventType.DELETED:
                # If this is a delete, save the old metadata for forensics
                if event.src_path in self.baseline:
                    old_metadata = self.baseline[event.src_path]
                    event.change_details = {
                        'deleted': {
                            'old': old_metadata,
                            'new': None
                        }
                    }
                self.baseline.pop(event.src_path, None)
                
            elif event.event_type in (EventType.CREATED, EventType.MODIFIED):
                # For create/modify, calculate what changed
                old_metadata = self.baseline.get(event.src_path, {})
                self._add_file_to_baseline(event.src_path)
                
                # Calculate what changed
                if old_metadata:
                    changes = {}
                    for key, new_value in self.baseline[event.src_path].items():
                        old_value = old_metadata.get(key)
                        if old_value != new_value:
                            changes[key] = {
                                'old': old_value,
                                'new': new_value
                            }
                    if changes:
                        event.change_details = changes
            
            elif event.event_type == EventType.RENAMED and event.dest_path:
                # Handle file rename in baseline
                if event.src_path in self.baseline:
                    old_metadata = self.baseline[event.src_path]
                    self.baseline[event.dest_path] = old_metadata
                    del self.baseline[event.src_path]
                    
                    # Record the rename in change details
                    event.change_details = {
                        'path': {
                            'old': event.src_path,
                            'new': event.dest_path
                        }
                    }
            
            # Check for suspicious patterns if enabled
            if self.enable_ransomware_detection:
                event_dict = event.to_dict()
                alert = self.ransomware_detector.analyze_event(event_dict)
                if alert:
                    self._trigger_alert(alert)
            
            # Trigger callbacks
            for callback in self.callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
    
    def _trigger_alert(self, alert_data: Dict) -> None:
        """Trigger an alert to all registered alert callbacks."""
        if not self.alert_callbacks:
            logger.warning("No alert callbacks registered. Alert suppressed.")
            
        # Add timestamp if not present
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.utcnow().isoformat()
            
        # Trigger all registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def add_alert_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Register a callback function to be called when an alert is triggered.

        Args:
            callback: Function that takes a dictionary containing alert details
        """
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)

# Import monitors here to avoid circular imports
from .platform_utils import get_platform_watcher, get_critical_paths, get_file_owner, get_process_info
from .monitors import BaseMonitor  # Keep BaseMonitor for backward compatibility
{{ ... }}
