""
File Integrity Monitoring - Monitors

This module contains the monitoring implementations for different types of
file system and registry monitoring.
"""
import os
import time
import logging
import threading
import win32file
import win32con
import win32event
import pywintypes
from typing import Optional, Dict, Any, Callable, List
from pathlib import Path
from queue import Queue, Empty

from .core import FIMEngine, FileEvent, EventType

logger = logging.getLogger(__name__)

class BaseMonitor(threading.Thread):
    """Base class for all monitoring implementations."""
    
    def __init__(self, path: str, engine: FIMEngine):
        """
        Initialize the monitor.
        
        Args:
            path: Path to monitor (file, directory, or registry key)
            engine: Reference to the FIM engine
        """
        super().__init__(daemon=True)
        self.path = os.path.normpath(path)
        self.engine = engine
        self._stop_event = threading.Event()
        self._initialized = False
        
        # Event queue for processing in a separate thread
        self._event_queue = Queue()
        self._event_processor = threading.Thread(
            target=self._process_events,
            daemon=True
        )
    
    def start(self) -> None:
        """Start the monitor."""
        if not self._initialized:
            self._initialize()
            self._initialized = True
        
        if not self.is_alive():
            super().start()
            self._event_processor.start()
            logger.info(f"Started monitoring: {self.path}")
    
    def stop(self) -> None:
        """Stop the monitor."""
        self._stop_event.set()
        if self.is_alive():
            self.join()
        logger.info(f"Stopped monitoring: {self.path}")
    
    def _initialize(self) -> None:
        """Initialize the monitor. Must be implemented by subclasses."""
        raise NotImplementedError
    
    def run(self) -> None:
        """Main monitoring loop. Must be implemented by subclasses."""
        raise NotImplementedError
    
    def _process_events(self) -> None:
        """Process events from the queue in a separate thread."""
        while not self._stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=1.0)
                if event:
                    self.engine._handle_event(event)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
    
    def _queue_event(self, event: FileEvent) -> None:
        """Add an event to the processing queue."""
        self._event_queue.put(event)


class FileMonitor(BaseMonitor):
    """Monitors a single file for changes."""
    
    def _initialize(self) -> None:
        """Initialize file monitoring."""
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")
        
        # Get initial file stats
        self._last_modified = os.path.getmtime(self.path)
        self._last_size = os.path.getsize(self.path)
    
    def run(self) -> None:
        """Monitor the file for changes."""
        while not self._stop_event.is_set():
            try:
                # Check if file still exists
                if not os.path.exists(self.path):
                    event = FileEvent(
                        event_type=EventType.DELETED,
                        src_path=self.path,
                        file_size=self._last_size,
                        last_modified=self._last_modified
                    )
                    self._queue_event(event)
                    break  # Stop monitoring if file is deleted
                
                # Check for modifications
                current_mtime = os.path.getmtime(self.path)
                current_size = os.path.getsize(self.path)
                
                if current_mtime > self._last_modified or current_size != self._last_size:
                    event_type = EventType.MODIFIED
                    
                    # Check if this is a complete rewrite (size changed to 0 then back)
                    if current_size == 0 and self._last_size > 0:
                        event_type = EventType.CREATED  # Treated as a new file
                    
                    event = FileEvent(
                        event_type=event_type,
                        src_path=self.path,
                        file_size=current_size,
                        last_modified=current_mtime,
                        checksum=self.engine._calculate_checksum(self.path)
                    )
                    self._queue_event(event)
                    
                    # Update last known state
                    self._last_modified = current_mtime
                    self._last_size = current_size
                
                # Sleep for the scan interval
                time.sleep(self.engine.scan_interval)
                
            except (OSError, IOError) as e:
                logger.error(f"Error monitoring file {self.path}: {e}")
                time.sleep(5)  # Wait before retrying
            except Exception as e:
                logger.error(f"Unexpected error in file monitor for {self.path}: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying


class DirectoryMonitor(BaseMonitor):
    """Monitors a directory and its subdirectories for changes."""
    
    def __init__(self, path: str, engine: FIMEngine, recursive: bool = True):
        """
        Initialize directory monitoring.
        
        Args:
            path: Directory path to monitor
            engine: Reference to the FIM engine
            recursive: If True, monitor subdirectories (default: True)
        """
        super().__init__(path, engine)
        self.recursive = recursive
        self._watchers: Dict[str, FileSystemWatcher] = {}
    
    def _initialize(self) -> None:
        """Initialize directory monitoring."""
        if not os.path.isdir(self.path):
            raise NotADirectoryError(f"Directory not found: {self.path}")
        
        # Set up the initial watch
        self._setup_watcher(self.path)
        
        # If recursive, set up watchers for all subdirectories
        if self.recursive:
            self._watch_subdirectories(self.path)
    
    def _setup_watcher(self, path: str) -> None:
        """Set up a file system watcher for the given directory."""
        if path in self._watchers:
            return
            
        try:
            watcher = FileSystemWatcher(path, self.engine, self.recursive)
            self._watchers[path] = watcher
            logger.debug(f"Set up watcher for directory: {path}")
        except Exception as e:
            logger.error(f"Failed to set up watcher for {path}: {e}")
    
    def _watch_subdirectories(self, root_path: str) -> None:
        """Recursively set up watchers for all subdirectories."""
        try:
            for entry in os.scandir(root_path):
                if entry.is_dir() and not entry.is_symlink():
                    dir_path = os.path.normpath(entry.path)
                    if not self.engine._should_ignore(dir_path):
                        self._setup_watcher(dir_path)
                        if self.recursive:
                            self._watch_subdirectories(dir_path)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not scan directory {root_path}: {e}")
    
    def run(self) -> None:
        """Main monitoring loop for directory changes."""
        # The actual monitoring is done by the FileSystemWatcher threads
        # This thread just manages the watchers and handles cleanup
        while not self._stop_event.is_set():
            try:
                # Check for new subdirectories (if recursive)
                if self.recursive:
                    self._check_for_new_directories()
                
                # Check if any watchers need to be restarted
                self._check_watchers()
                
                # Sleep for a bit before checking again
                time.sleep(self.engine.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in directory monitor for {self.path}: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying
    
    def _check_for_new_directories(self) -> None:
        """Check for and monitor new subdirectories."""
        try:
            for root, dirs, _ in os.walk(self.path, topdown=True):
                # Filter out directories that should be ignored
                dirs[:] = [d for d in dirs 
                          if not self.engine._should_ignore(os.path.join(root, d))]
                
                for dir_name in dirs:
                    dir_path = os.path.normpath(os.path.join(root, dir_name))
                    if dir_path not in self._watchers and not self.engine._should_ignore(dir_path):
                        self._setup_watcher(dir_path)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not check for new directories in {self.path}: {e}")
    
    def _check_watchers(self) -> None:
        """Check if any watchers need to be restarted."""
        for path, watcher in list(self._watchers.items()):
            if not watcher.is_alive():
                logger.warning(f"Watcher for {path} died, restarting...")
                del self._watchers[path]
                if os.path.isdir(path):
                    self._setup_watcher(path)
    
    def stop(self) -> None:
        """Stop all watchers and clean up."""
        super().stop()
        for watcher in self._watchers.values():
            watcher.stop()
        self._watchers.clear()


class FileSystemWatcher(threading.Thread):
    """Watches a single directory for file system changes using Windows API."""
    
    # Map Windows file action constants to our event types
    _ACTION_MAP = {
        1: EventType.CREATED,    # FILE_ACTION_ADDED
        2: EventType.DELETED,    # FILE_ACTION_REMOVED
        3: EventType.MODIFIED,   # FILE_ACTION_MODIFIED
        4: EventType.RENAMED,    # FILE_ACTION_RENAMED_OLD_NAME
        5: EventType.RENAMED     # FILE_ACTION_RENAMED_NEW_NAME
    }
    
    def __init__(self, path: str, engine: FIMEngine, watch_subtree: bool = False):
        """
        Initialize the file system watcher.
        
        Args:
            path: Directory path to watch
            engine: Reference to the FIM engine
            watch_subtree: If True, watch subdirectories (Windows only)
        """
        super().__init__(daemon=True)
        self.path = os.path.normpath(path)
        self.engine = engine
        self.watch_subtree = watch_subtree
        self._stop_event = threading.Event()
        self._buffer = None
        self._overlapped = None
        self._dir_handle = None
        
        # Track rename operations (old_name -> new_name)
        self._pending_renames = {}
        
        # Start the thread
        self.start()
    
    def run(self) -> None:
        """Main monitoring loop."""
        try:
            # Set up the directory handle and overlapped structure
            self._setup()
            
            # Main monitoring loop
            while not self._stop_event.is_set():
                try:
                    # Wait for a change notification
                    result = win32file.GetOverlappedResult(
                        self._dir_handle,
                        self._overlapped,
                        True  # Wait for the operation to complete
                    )
                    
                    if result == 0:
                        continue
                    
                    # Process the change notifications
                    self._process_changes()
                    
                    # Queue the next notification
                    self._queue_notification()
                    
                except pywintypes.error as e:
                    if e.winerror != 995:  # ERROR_OPERATION_ABORTED
                        logger.error(f"Error in file system watcher for {self.path}: {e}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in file system watcher for {self.path}: {e}", 
                               exc_info=True)
                    time.sleep(1)  # Prevent tight loop on errors
        finally:
            self._cleanup()
    
    def _setup(self) -> None:
        """Set up the directory handle and overlapped structure."""
        # Create a directory handle
        self._dir_handle = win32file.CreateFile(
            self.path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
            None
        )
        
        # Set up the overlapped structure
        self._overlapped = pywintypes.OVERLAPPED()
        self._overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
        
        # Allocate a buffer for the change notifications
        self._buffer = win32file.AllocateReadBuffer(8192)
        
        # Queue the first notification
        self._queue_notification()
    
    def _queue_notification(self) -> None:
        """Queue an asynchronous directory change notification."""
        win32file.ReadDirectoryChangesW(
            self._dir_handle,
            self._buffer,
            self.watch_subtree,
            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
            win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
            win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
            win32con.FILE_NOTIFY_CHANGE_SIZE |
            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
            win32con.FILE_NOTIFY_CHANGE_SECURITY,
            self._overlapped,
            None
        )
    
    def _process_changes(self) -> None:
        """Process the queued change notifications."""
        # Get the results
        nbytes = win32file.GetOverlappedResult(
            self._dir_handle,
            self._overlapped,
            True
        )
        
        if nbytes == 0:
            return
        
        # Parse the results
        results = win32file.FILE_NOTIFY_INFORMATION(self._buffer, nbytes)
        
        # Process each change
        for action, filename in results:
            # Skip if we should ignore this file
            file_path = os.path.normpath(os.path.join(self.path, filename))
            if self.engine._should_ignore(file_path):
                continue
            
            # Map the action to our event type
            event_type = self._ACTION_MAP.get(action)
            if not event_type:
                continue
            
            # Handle the event
            self._handle_file_event(event_type, file_path, filename)
    
    def _handle_file_event(self, event_type: EventType, file_path: str, filename: str) -> None:
        """Handle a file system event."""
        try:
            # Handle renames (which come in pairs)
            if event_type == EventType.RENAMED:
                # If we have a pending rename with the same cookie, this is the new name
                if hasattr(filename, 'cookie') and filename.cookie in self._pending_renames:
                    old_path = self._pending_renames.pop(filename.cookie)
                    
                    # Create a rename event
                    event = FileEvent(
                        event_type=EventType.RENAMED,
                        src_path=old_path,
                        dest_path=file_path,
                        is_directory=os.path.isdir(file_path)
                    )
                    self.engine._queue_event(event)
                else:
                    # This is the old name of a rename operation
                    if hasattr(filename, 'cookie'):
                        self._pending_renames[filename.cookie] = file_path
                return
            
            # For other event types, create the appropriate event
            is_dir = os.path.isdir(file_path)
            file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
            last_modified = os.path.getmtime(file_path) if os.path.exists(file_path) else 0
            
            event = FileEvent(
                event_type=event_type,
                src_path=file_path,
                is_directory=is_dir,
                file_size=file_size,
                last_modified=last_modified,
                checksum=self.engine._calculate_checksum(file_path) if not is_dir else None
            )
            
            # Queue the event for processing
            self.engine._queue_event(event)
            
        except (OSError, IOError) as e:
            # File might have been deleted or is inaccessible
            if event_type != EventType.DELETED:
                logger.debug(f"Could not process {event_type.name} event for {file_path}: {e}")
    
    def stop(self) -> None:
        """Stop the watcher and clean up resources."""
        self._stop_event.set()
        self._cleanup()
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        if hasattr(self, '_overlapped') and self._overlapped and self._overlapped.hEvent:
            try:
                win32event.SetEvent(self._overlapped.hEvent)
                win32api.CloseHandle(self._overlapped.hEvent)
            except:
                pass
        
        if hasattr(self, '_dir_handle') and self._dir_handle:
            try:
                win32file.CancelIo(self._dir_handle)
                win32file.CloseHandle(self._dir_handle)
            except:
                pass


class RegistryMonitor(BaseMonitor):
    """Monitors Windows registry keys for changes."""
    
    def __init__(self, key_path: str, engine: FIMEngine, watch_subkeys: bool = True):
        """
        Initialize registry monitoring.
        
        Args:
            key_path: Full path to the registry key to monitor (e.g., 'HKEY_LOCAL_MACHINE\\Software')
            engine: Reference to the FIM engine
            watch_subkeys: If True, monitor all subkeys (default: True)
        """
        super().__init__(key_path, engine)
        self.watch_subkeys = watch_subkeys
        self._watchers: Dict[str, threading.Thread] = {}
    
    def _initialize(self) -> None:
        """Initialize registry monitoring."""
        # This is a placeholder - actual implementation would use Windows API
        # to monitor registry changes
        logger.warning("Registry monitoring is not fully implemented on this platform")
    
    def run(self) -> None:
        """Monitor registry for changes."""
        # This is a placeholder - actual implementation would use Windows API
        # to monitor registry changes
        while not self._stop_event.is_set():
            time.sleep(self.engine.scan_interval)
    
    def stop(self) -> None:
        """Stop monitoring the registry."""
        super().stop()
        for watcher in self._watchers.values():
            watcher.stop()
        self._watchers.clear()
