"""
File system monitoring for EDR.
Tracks file and directory changes in real-time.
"""
import os
import time
import hashlib
import fnmatch
from typing import Dict, Any, List, Set, Optional
from pathlib import Path
import threading

# Platform-specific imports
try:
    import pyinotify
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from .base_monitor import BaseMonitor

class FileMonitor(BaseMonitor):
    """Monitors file system changes in real-time."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the file monitor."""
        super().__init__(config)
        self.watch_dirs = self.config.get('watch_directories', ['/'])
        self.exclude_patterns = self.config.get('exclude_patterns', [])
        self.max_file_size = self.config.get('max_file_size_mb', 50) * 1024 * 1024  # Convert MB to bytes
        self.collect_hashes = self.config.get('collect_hashes', True)
        self.hash_algorithms = self.config.get('hash_algorithms', ['md5', 'sha1', 'sha256'])
        
        # Platform-specific initialization
        self.observer = None
        self.wm = None
        self.notifier = None
        
    def start(self) -> None:
        """Start the file system monitoring."""
        if self.running:
            self.logger.warning("File monitor is already running")
            return
            
        self.running = True
        
        # Choose the appropriate monitoring method based on platform
        if INOTIFY_AVAILABLE and os.name == 'posix':
            self._start_inotify()
        elif WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self.logger.warning("No suitable file monitoring backend available. Using polling.")
            self.thread = threading.Thread(target=self._polling_monitor, daemon=True)
            self.thread.start()
    
    def _start_inotify(self) -> None:
        """Start inotify-based monitoring (Linux)."""
        try:
            self.wm = pyinotify.WatchManager()
            self.notifier = pyinotify.ThreadedNotifier(
                self.wm,
                self._handle_inotify_event
            )
            
            # Watch for all events
            mask = (pyinotify.IN_CREATE | pyinotify.IN_DELETE | 
                   pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM | 
                   pyinotify.IN_MOVED_TO | pyinotify.IN_ATTRIB)
            
            # Add watches for all specified directories
            for directory in self.watch_dirs:
                if os.path.isdir(directory):
                    self.wm.add_watch(
                        directory,
                        mask,
                        rec=True,
                        auto_add=True
                    )
            
            self.notifier.start()
            self.logger.info("Started inotify-based file monitoring")
            
        except Exception as e:
            self.logger.error(f"Failed to start inotify: {e}")
            raise
    
    def _start_watchdog(self) -> None:
        """Start watchdog-based monitoring (cross-platform)."""
        try:
            self.observer = Observer()
            
            for directory in self.watch_dirs:
                if os.path.isdir(directory):
                    handler = WatchdogHandler(self)
                    self.observer.schedule(
                        handler,
                        directory,
                        recursive=True
                    )
            
            self.observer.start()
            self.logger.info("Started watchdog-based file monitoring")
            
        except Exception as e:
            self.logger.error(f"Failed to start watchdog: {e}")
            raise
    
    def _polling_monitor(self) -> None:
        """Fallback polling-based monitoring."""
        self.logger.info("Starting polling-based file monitoring")
        known_files = set()
        
        while self.running:
            try:
                current_files = set()
                
                # Scan all watch directories
                for directory in self.watch_dirs:
                    if os.path.isdir(directory):
                        for root, _, files in os.walk(directory):
                            # Skip excluded directories
                            if self._is_excluded(root):
                                continue
                                
                            for file in files:
                                file_path = os.path.join(root, file)
                                current_files.add(file_path)
                                
                                # Check for new or modified files
                                if file_path not in known_files:
                                    self._handle_file_event('created', file_path)
                                elif os.path.getmtime(file_path) > time.time() - 5:  # Modified in last 5s
                                    self._handle_file_event('modified', file_path)
                
                # Check for deleted files
                for file_path in known_files - current_files:
                    self._handle_file_event('deleted', file_path)
                
                known_files = current_files
                time.sleep(5)  # Poll every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in polling monitor: {e}")
                time.sleep(10)
    
    def stop(self) -> None:
        """Stop the file system monitoring."""
        self.running = False
        
        if self.notifier:
            self.notifier.stop()
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        super().stop()
    
    def _handle_inotify_event(self, event):
        """Handle inotify events."""
        if not self.running:
            return
            
        try:
            path = event.pathname
            
            # Skip excluded paths
            if self._is_excluded(path):
                return
            
            # Map inotify events to our event types
            if event.mask & (pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO):
                self._handle_file_event('created', path, is_dir=event.dir)
            elif event.mask & (pyinotify.IN_DELETE | pyinotify.IN_MOVED_FROM):
                self._handle_file_event('deleted', path, is_dir=event.dir)
            elif event.mask & pyinotify.IN_MODIFY:
                self._handle_file_event('modified', path, is_dir=event.dir)
            elif event.mask & pyinotify.IN_ATTRIB:
                self._handle_file_event('attributes_changed', path, is_dir=event.dir)
                
        except Exception as e:
            self.logger.error(f"Error handling inotify event: {e}")
    
    def _handle_file_event(self, event_type: str, path: str, is_dir: bool = None) -> None:
        """Handle a file system event."""
        try:
            if is_dir is None:
                is_dir = os.path.isdir(path)
            
            # Skip if path is excluded
            if self._is_excluded(path):
                return
            
            # Skip directories for certain event types
            if is_dir and event_type in ['modified', 'attributes_changed']:
                return
            
            # Get file stats
            try:
                stat = os.stat(path)
                size = stat.st_size
                mtime = stat.st_mtime
                atime = stat.st_atime
                ctime = stat.st_ctime
                uid = stat.st_uid
                gid = stat.st_gid
                mode = stat.st_mode
            except (OSError, AttributeError):
                # File might have been deleted
                if event_type != 'deleted':
                    return
                size = mtime = atime = ctime = uid = gid = mode = 0
            
            # Skip files larger than max size
            if not is_dir and size > self.max_file_size:
                return
            
            # Calculate hashes for new or modified files
            hashes = {}
            if event_type in ['created', 'modified'] and not is_dir and self.collect_hashes:
                hashes = self._calculate_hashes(path)
            
            # Create file event
            event = self._create_event(
                event_type=f'file_{event_type}',
                data={
                    'path': path,
                    'is_directory': is_dir,
                    'size': size,
                    'modified_time': mtime,
                    'access_time': atime,
                    'creation_time': ctime,
                    'user_id': uid,
                    'group_id': gid,
                    'mode': mode,
                    'hashes': hashes
                }
            )
            
            self._notify_handlers(event)
            
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}", exc_info=True)
    
    def _is_excluded(self, path: str) -> bool:
        """Check if a path matches any exclude patterns."""
        path = os.path.normpath(path)
        
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
            
            # Also check parent directories
            parts = Path(path).parts
            for i in range(1, len(parts)):
                if fnmatch.fnmatch(os.path.join(*parts[:i+1]), pattern):
                    return True
        
        return False
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes using specified algorithms."""
        hashes = {}
        
        try:
            if not os.path.isfile(file_path):
                return hashes
                
            # Initialize hash objects
            hash_objects = {}
            for algo in self.hash_algorithms:
                if hasattr(hashlib, algo):
                    hash_objects[algo] = getattr(hashlib, algo)()
            
            if not hash_objects:
                return hashes
            
            # Read file in chunks
            chunk_size = 65536  # 64KB chunks
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Get hex digests
            hashes = {algo: hash_obj.hexdigest() 
                     for algo, hash_obj in hash_objects.items()}
            
        except Exception as e:
            self.logger.warning(f"Error calculating hashes for {file_path}: {e}")
        
        return hashes


class WatchdogHandler(FileSystemEventHandler):
    """Handler for watchdog file system events."""
    
    def __init__(self, monitor):
        self.monitor = monitor
    
    def on_created(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event('created', event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event('deleted', event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event('modified', event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event('deleted', event.src_path)
            self.monitor._handle_file_event('created', event.dest_path)
