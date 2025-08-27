"""
File Monitor Module

This module provides real-time monitoring of file system changes, including file
creation, modification, deletion, and permission changes.
"""

import os
import sys
import time
import hashlib
import logging
import platform
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import json
from datetime import datetime

# Platform-specific imports
if platform.system() == 'Windows':
    import win32file
    import win32con
    import pywintypes
else:
    import select
    import pyinotify

logger = logging.getLogger('fim.monitor')

class EventType(Enum):
    """Types of file system events that can be monitored."""
    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    MOVED = auto()
    ATTRIBUTES_CHANGED = auto()
    PERMISSIONS_CHANGED = auto()
    SECURITY_CHANGED = auto()

@dataclass
class FileEvent:
    """Represents a file system event."""
    event_type: EventType
    src_path: str
    dest_path: Optional[str] = None
    is_directory: bool = False
    timestamp: float = field(default_factory=time.time)
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    old_attributes: Optional[Dict[str, Any]] = None
    new_attributes: Optional[Dict[str, Any]] = None
    process_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        return {
            'event_type': self.event_type.name,
            'src_path': self.src_path,
            'dest_path': self.dest_path,
            'is_directory': self.is_directory,
            'timestamp': self.timestamp,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'old_attributes': self.old_attributes,
            'new_attributes': self.new_attributes,
            'process_info': self.process_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileEvent':
        """Create a FileEvent from a dictionary."""
        return cls(
            event_type=EventType[data['event_type']],
            src_path=data['src_path'],
            dest_path=data.get('dest_path'),
            is_directory=data.get('is_directory', False),
            timestamp=data.get('timestamp', time.time()),
            file_size=data.get('file_size'),
            file_hash=data.get('file_hash'),
            old_attributes=data.get('old_attributes'),
            new_attributes=data.get('new_attributes'),
            process_info=data.get('process_info')
        )

class FileMonitor:
    """Monitors file system changes in real-time."""
    
    def __init__(self, paths: List[str] = None):
        """Initialize the file monitor.
        
        Args:
            paths: List of directories or files to monitor
        """
        self.paths = [Path(p).resolve() for p in (paths or [])]
        self.running = False
        self.callbacks: List[Callable[[FileEvent], None]] = []
        self._watchers = {}
        self._event_queue = []
        self._lock = None  # Placeholder for thread safety
        
        # Platform-specific initialization
        if platform.system() == 'Windows':
            self._init_windows()
        else:
            self._init_linux()
    
    def _init_windows(self) -> None:
        """Initialize Windows-specific monitoring components."""
        self._change_handles = {}
        self._overlapped = {}
        self._buffer = win32file.AllocateReadBuffer(4096)
        
        # Windows-specific event masks
        self.FILE_LIST_DIRECTORY = win32con.FILE_LIST_DIRECTORY
        self.FILE_NOTIFY_CHANGE_FILE_NAME = win32con.FILE_NOTIFY_CHANGE_FILE_NAME
        self.FILE_NOTIFY_CHANGE_DIR_NAME = win32con.FILE_NOTIFY_CHANGE_DIR_NAME
        self.FILE_NOTIFY_CHANGE_ATTRIBUTES = win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES
        self.FILE_NOTIFY_CHANGE_SIZE = win32con.FILE_NOTIFY_CHANGE_SIZE
        self.FILE_NOTIFY_CHANGE_LAST_WRITE = win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
        self.FILE_NOTIFY_CHANGE_SECURITY = win32con.FILE_NOTIFY_CHANGE_SECURITY
        
        self._event_mapping = {
            win32con.FILE_ACTION_ADDED: EventType.CREATED,
            win32con.FILE_ACTION_REMOVED: EventType.DELETED,
            win32con.FILE_ACTION_MODIFIED: EventType.MODIFIED,
            win32con.FILE_ACTION_RENAMED_OLD_NAME: EventType.MOVED,
            win32con.FILE_ACTION_RENAMED_NEW_NAME: EventType.MOVED
        }
    
    def _init_linux(self) -> None:
        """Initialize Linux-specific monitoring components."""
        self.wm = pyinotify.WatchManager()
        self.notifier = None
        
        # Linux event masks
        self.IN_CREATE = pyinotify.IN_CREATE
        self.IN_DELETE = pyinotify.IN_DELETE
        self.IN_MODIFY = pyinotify.IN_MODIFY
        self.IN_MOVED_FROM = pyinotify.IN_MOVED_FROM
        self.IN_MOVED_TO = pyinotify.IN_MOVED_TO
        self.IN_ATTRIB = pyinotify.IN_ATTRIB
        self.IN_CLOSE_WRITE = pyinotify.IN_CLOSE_WRITE
        
        self._event_mapping = {
            self.IN_CREATE: EventType.CREATED,
            self.IN_DELETE: EventType.DELETED,
            self.IN_MODIFY: EventType.MODIFIED,
            self.IN_MOVED_FROM: EventType.MOVED,
            self.IN_MOVED_TO: EventType.MOVED,
            self.IN_ATTRIB: EventType.ATTRIBUTES_CHANGED,
            self.IN_CLOSE_WRITE: EventType.MODIFIED
        }
    
    def add_callback(self, callback: Callable[[FileEvent], None]) -> None:
        """Add a callback function to be called when file events occur."""
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[FileEvent], None]) -> bool:
        """Remove a callback function."""
        try:
            self.callbacks.remove(callback)
            return True
        except ValueError:
            return False
    
    def start(self) -> None:
        """Start monitoring the file system."""
        if self.running:
            logger.warning("File monitor is already running")
            return
            
        self.running = True
        
        if platform.system() == 'Windows':
            self._start_windows()
        else:
            self._start_linux()
        
        logger.info(f"File monitor started on {len(self.paths)} paths")
    
    def stop(self) -> None:
        """Stop monitoring the file system."""
        if not self.running:
            return
            
        self.running = False
        
        if platform.system() == 'Windows':
            self._stop_windows()
        else:
            self._stop_linux()
        
        logger.info("File monitor stopped")
    
    def _start_windows(self) -> None:
        """Start monitoring on Windows."""
        for path in self.paths:
            try:
                # Convert path to Windows format
                path_str = str(path).replace('/', '\\')
                
                # Get a handle to the directory
                handle = win32file.CreateFile(
                    path_str,
                    self.FILE_LIST_DIRECTORY,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                    None
                )
                
                # Set up overlapped structure
                overlapped = pywintypes.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, False, 0, None)
                
                # Start monitoring
                win32file.ReadDirectoryChangesW(
                    handle,
                    self._buffer,
                    True,  # Watch subdirectories
                    self.FILE_NOTIFY_CHANGE_FILE_NAME |
                    self.FILE_NOTIFY_CHANGE_DIR_NAME |
                    self.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    self.FILE_NOTIFY_CHANGE_SIZE |
                    self.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    self.FILE_NOTIFY_CHANGE_SECURITY,
                    overlapped,
                    None
                )
                
                # Store handles for later cleanup
                self._change_handles[path] = handle
                self._overlapped[path] = overlapped
                
                logger.debug(f"Started monitoring {path}")
                
            except Exception as e:
                logger.error(f"Failed to monitor {path}: {e}")
    
    def _stop_windows(self) -> None:
        """Stop monitoring on Windows."""
        for handle in self._change_handles.values():
            try:
                handle.Close()
            except Exception as e:
                logger.error(f"Error closing handle: {e}")
        
        for overlapped in self._overlapped.values():
            try:
                win32api.CloseHandle(overlapped.hEvent)
            except Exception as e:
                logger.error(f"Error closing event handle: {e}")
        
        self._change_handles.clear()
        self._overlapped.clear()
    
    def _process_windows_events(self, timeout: int = 1000) -> None:
        """Process Windows file system events."""
        if not self._change_handles:
            return
            
        handles = [ov.hEvent for ov in self._overlapped.values()]
        if not handles:
            return
            
        rc = win32event.WaitForMultipleObjects(
            handles,
            False,  # Wait for any event
            timeout
        )
        
        if rc == win32event.WAIT_TIMEOUT:
            return
            
        idx = rc - win32event.WAIT_OBJECT_0
        if 0 <= idx < len(handles):
            path = list(self._overlapped.keys())[idx]
            overlapped = self._overlapped[path]
            
            try:
                # Get the results
                nbytes = win32file.GetOverlappedResult(
                    self._change_handles[path],
                    overlapped,
                    True  # Wait for completion
                )
                
                if nbytes == 0:
                    return
                
                # Parse the events
                results = win32file.FILE_NOTIFY_INFORMATION(self._buffer, nbytes)
                
                for action, filename in results:
                    event_type = self._event_mapping.get(action)
                    if not event_type:
                        continue
                        
                    full_path = str(Path(path) / filename)
                    is_dir = os.path.isdir(full_path)
                    
                    event = FileEvent(
                        event_type=event_type,
                        src_path=full_path,
                        is_directory=is_dir,
                        timestamp=time.time()
                    )
                    
                    # For move events, we need to handle the pair of events
                    if action == win32con.FILE_ACTION_RENAMED_OLD_NAME:
                        self._last_move_src = (full_path, is_dir)
                        continue
                    elif action == win32con.FILE_ACTION_RENAMED_NEW_NAME and hasattr(self, '_last_move_src'):
                        old_path, old_is_dir = self._last_move_src
                        event = FileEvent(
                            event_type=EventType.MOVED,
                            src_path=old_path,
                            dest_path=full_path,
                            is_directory=old_is_dir,
                            timestamp=time.time()
                        )
                        delattr(self, '_last_move_src')
                    
                    self._queue_event(event)
                
                # Queue up the next read
                win32file.ReadDirectoryChangesW(
                    self._change_handles[path],
                    self._buffer,
                    True,
                    self.FILE_NOTIFY_CHANGE_FILE_NAME |
                    self.FILE_NOTIFY_CHANGE_DIR_NAME |
                    self.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    self.FILE_NOTIFY_CHANGE_SIZE |
                    self.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    self.FILE_NOTIFY_CHANGE_SECURITY,
                    overlapped,
                    None
                )
                
            except Exception as e:
                logger.error(f"Error processing Windows events: {e}")
    
    def _start_linux(self) -> None:
        """Start monitoring on Linux using inotify."""
        # Define the event handler
        class EventHandler(pyinotify.ProcessEvent):
            def __init__(self, callback):
                self.callback = callback
                super().__init__()
            
            def process_default(self, event):
                event_type = self._event_mapping.get(event.mask)
                if not event_type:
                    return
                
                file_event = FileEvent(
                    event_type=event_type,
                    src_path=event.pathname,
                    is_directory=event.dir,
                    timestamp=time.time()
                )
                
                # Handle move events
                if event_type == EventType.MOVED:
                    if hasattr(self, '_last_move_from'):
                        # This is the second part of a move (TO)
                        old_path, old_dir = self._last_move_from
                        file_event = FileEvent(
                            event_type=EventType.MOVED,
                            src_path=old_path,
                            dest_path=event.pathname,
                            is_directory=old_dir,
                            timestamp=time.time()
                        )
                        delattr(self, '_last_move_from')
                    else:
                        # This is the first part of a move (FROM)
                        self._last_move_from = (event.pathname, event.dir)
                        return
                
                self.callback(file_event)
        
        # Set up the notifier
        mask = (
            self.IN_CREATE | self.IN_DELETE | self.IN_MODIFY |
            self.IN_MOVED_FROM | self.IN_MOVED_TO |
            self.IN_ATTRIB | self.IN_CLOSE_WRITE
        )
        
        self.notifier = pyinotify.AsyncNotifier(
            self.wm,
            EventHandler(self._queue_event)
        )
        
        # Add watches for all paths
        for path in self.paths:
            try:
                self.wm.add_watch(
                    str(path),
                    mask,
                    rec=True,  # Recursively watch subdirectories
                    auto_add=True  # Automatically add new subdirectories
                )
                logger.debug(f"Started monitoring {path}")
            except Exception as e:
                logger.error(f"Failed to monitor {path}: {e}")
    
    def _stop_linux(self) -> None:
        """Stop monitoring on Linux."""
        if self.notifier:
            self.notifier.stop()
            self.notifier = None
        
        if hasattr(self, 'wm'):
            self.wm.rm_watch(list(self.wm.watches.keys()))
    
    def _queue_event(self, event: FileEvent) -> None:
        """Queue an event for processing."""
        self._event_queue.append(event)
    
    def process_events(self, timeout: float = 0.1) -> None:
        """Process any pending file system events."""
        if platform.system() == 'Windows':
            self._process_windows_events(int(timeout * 1000))
        else:
            if self.notifier:
                self.notifier.process_events()
                if self.notifier.check_events(timeout_ms=int(timeout * 1000)):
                    self.notifier.read_events()
                    self.notifier.process_events()
        
        # Process any queued events
        while self._event_queue:
            event = self._event_queue.pop(0)
            self._notify_callbacks(event)
    
    def _notify_callbacks(self, event: FileEvent) -> None:
        """Notify all registered callbacks of a file event."""
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in file event callback: {e}", exc_info=True)
    
    def run(self) -> None:
        """Run the file monitor in the current thread."""
        self.start()
        
        try:
            while self.running:
                self.process_events(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
