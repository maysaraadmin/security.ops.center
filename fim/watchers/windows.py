"""
Windows-specific file system watcher implementation.

This module provides a file system watcher for Windows that uses the Windows API
for efficient change notification.
"""
import os
import threading
import logging
import win32file
import win32con
import win32event
import pywintypes
from typing import Callable, Dict, Any, Optional, List, Tuple

from ..core import EventType

logger = logging.getLogger(__name__)

class WindowsFileSystemWatcher:
    """File system watcher implementation for Windows using the Windows API."""
    
    # Map Windows file action constants to our event types
    _ACTION_MAP = {
        1: EventType.CREATED,    # FILE_ACTION_ADDED
        2: EventType.DELETED,    # FILE_ACTION_REMOVED
        3: EventType.MODIFIED,   # FILE_ACTION_MODIFIED
        4: EventType.RENAMED,    # FILE_ACTION_RENAMED_OLD_NAME
        5: EventType.RENAMED     # FILE_ACTION_RENAMED_NEW_NAME
    }
    
    def __init__(self, path: str, callback: Callable, recursive: bool = True):
        """
        Initialize the Windows file system watcher.
        
        Args:
            path: Directory path to watch
            callback: Function to call when changes are detected
            recursive: Whether to watch subdirectories (default: True)
        """
        self.path = os.path.normpath(path)
        self.callback = callback
        self.recursive = recursive
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._watchers: Dict[str, Any] = {}
    
    def start(self) -> None:
        """Start watching for file system changes."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Watcher is already running")
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Started watching directory: {self.path}")
    
    def stop(self) -> None:
        """Stop watching for file system changes."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning("Timed out waiting for watcher thread to stop")
        
        # Clean up any remaining watchers
        for watcher in self._watchers.values():
            try:
                if 'handle' in watcher and watcher['handle']:
                    win32file.FindCloseChangeNotification(watcher['handle'])
            except Exception as e:
                logger.error(f"Error cleaning up watcher: {e}")
        
        self._watchers.clear()
        logger.info(f"Stopped watching directory: {self.path}")
    
    def is_running(self) -> bool:
        """Check if the watcher is running."""
        return self._thread is not None and self._thread.is_alive()
    
    def _run(self) -> None:
        """Main watcher loop."""
        try:
            # Set up the initial directory handle and overlapped structure
            self._setup_watcher(self.path)
            
            # Main event loop
            while not self._stop_event.is_set():
                try:
                    # Wait for a change notification
                    handles = [w['handle'] for w in self._watchers.values()]
                    if not handles:
                        logger.warning("No active watchers, stopping")
                        break
                        
                    rc = win32event.WaitForMultipleObjects(
                        handles,
                        False,  # Wait for any
                        win32event.INFINITE if not self._stop_event.is_set() else 0
                    )
                    
                    if self._stop_event.is_set():
                        break
                        
                    if rc == win32event.WAIT_FAILED:
                        logger.error("WaitForMultipleObjects failed")
                        continue
                        
                    # Get the index of the handle that was signaled
                    idx = rc - win32event.WAIT_OBJECT_0
                    if 0 <= idx < len(handles):
                        # Find which watcher was triggered
                        path = list(self._watchers.keys())[idx]
                        self._process_changes(path)
                    
                except pywintypes.error as e:
                    if e.winerror != 995:  # ERROR_OPERATION_ABORTED
                        logger.error(f"Error in watcher: {e}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in watcher: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on errors
        finally:
            self._cleanup()
    
    def _setup_watcher(self, path: str) -> None:
        """Set up a watcher for the specified directory."""
        if path in self._watchers:
            return
            
        try:
            # Get a handle to the directory
            handle = win32file.CreateFile(
                path,
                win32file.FILE_LIST_DIRECTORY,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OVERLAPPED,
                None
            )
            
            # Set up the overlapped structure
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, False, 0, None)
            
            # Start watching the directory
            win32file.ReadDirectoryChangesW(
                handle,
                4096,  # Buffer size
                self.recursive,
                win32file.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32file.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32file.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32file.FILE_NOTIFY_CHANGE_SIZE |
                win32file.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32file.FILE_NOTIFY_CHANGE_SECURITY,
                overlapped,
                None
            )
            
            # Create a change notification handle
            change_handle = win32file.FindFirstChangeNotification(
                path,
                self.recursive,
                win32file.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32file.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32file.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32file.FILE_NOTIFY_CHANGE_SIZE |
                win32file.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32file.FILE_NOTIFY_CHANGE_SECURITY
            )
            
            # Save the watcher state
            self._watchers[path] = {
                'handle': change_handle,
                'dir_handle': handle,
                'overlapped': overlapped,
                'buffer': win32file.AllocateReadBuffer(4096)
            }
            
            logger.debug(f"Set up watcher for directory: {path}")
            
        except Exception as e:
            logger.error(f"Failed to set up watcher for {path}: {e}")
            if 'handle' in locals() and handle:
                win32file.CloseHandle(handle)
            if 'overlapped' in locals() and hasattr(overlapped, 'hEvent') and overlapped.hEvent:
                win32api.CloseHandle(overlapped.hEvent)
            raise
    
    def _process_changes(self, path: str) -> None:
        """Process changes in the specified directory."""
        if path not in self._watchers:
            return
            
        watcher = self._watchers[path]
        
        try:
            # Get the results of the overlapped operation
            nbytes = win32file.GetOverlappedResult(
                watcher['dir_handle'],
                watcher['overlapped'],
                True  # Wait for the operation to complete
            )
            
            if nbytes == 0:
                return
            
            # Parse the results
            results = win32file.FILE_NOTIFY_INFORMATION(watcher['buffer'], nbytes)
            
            # Process each change
            for action, filename in results:
                if self._stop_event.is_set():
                    break
                    
                # Skip if the filename is empty
                if not filename:
                    continue
                
                # Get the full path
                file_path = os.path.normpath(os.path.join(path, filename))
                
                # Map the action to our event type
                event_type = self._ACTION_MAP.get(action)
                if not event_type:
                    logger.debug(f"Unknown action: {action} for {file_path}")
                    continue
                
                # Call the callback with the event details
                try:
                    self.callback(event_type, file_path)
                except Exception as e:
                    logger.error(f"Error in callback for {file_path}: {e}", exc_info=True)
            
            # Queue up the next read
            self._queue_next_read(path)
            
        except pywintypes.error as e:
            if e.winerror != 995:  # ERROR_OPERATION_ABORTED
                logger.error(f"Error processing changes for {path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing changes for {path}: {e}", exc_info=True)
    
    def _queue_next_read(self, path: str) -> None:
        """Queue up the next asynchronous read."""
        if path not in self._watchers:
            return
            
        watcher = self._watchers[path]
        
        try:
            win32file.ReadDirectoryChangesW(
                watcher['dir_handle'],
                4096,  # Buffer size
                self.recursive,
                win32file.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32file.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32file.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32file.FILE_NOTIFY_CHANGE_SIZE |
                win32file.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32file.FILE_NOTIFY_CHANGE_SECURITY,
                watcher['overlapped'],
                None
            )
        except Exception as e:
            logger.error(f"Failed to queue next read for {path}: {e}")
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        for path, watcher in list(self._watchers.items()):
            try:
                if 'handle' in watcher and watcher['handle']:
                    win32file.FindCloseChangeNotification(watcher['handle'])
                if 'dir_handle' in watcher and watcher['dir_handle']:
                    win32file.CloseHandle(watcher['dir_handle'])
                if 'overlapped' in watcher and hasattr(watcher['overlapped'], 'hEvent') and watcher['overlapped'].hEvent:
                    win32api.CloseHandle(watcher['overlapped'].hEvent)
            except Exception as e:
                logger.error(f"Error cleaning up watcher for {path}: {e}")
        
        self._watchers.clear()
