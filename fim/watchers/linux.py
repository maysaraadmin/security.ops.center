"""
Linux-specific file system watcher implementation using inotify.

This module provides a file system watcher for Linux that uses the inotify API
for efficient change notification.
"""
import os
import sys
import time
import logging
import threading
import select
import ctypes
import ctypes.util
from typing import Callable, Dict, Any, Optional, List, Tuple

from ..core import EventType

logger = logging.getLogger(__name__)

# Constants from linux/inotify.h
IN_CLOEXEC = 0o2000000
IN_NONBLOCK = 0o0004000
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_MASK_ADD = 0x20000000
IN_ISDIR = 0x40000000
IN_ONESHOT = 0x80000000

# Event masks
IN_ALL_EVENTS = (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
                 IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO |
                 IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)

# inotify event structure (from linux/inotify.h)
class InotifyEvent(ctypes.Structure):
    _fields_ = [
        ('wd', ctypes.c_int),      # Watch descriptor
        ('mask', ctypes.c_uint32), # Mask of events
        ('cookie', ctypes.c_uint32), # Unique cookie
        ('length', ctypes.c_uint32), # Length of name
        ('name', ctypes.c_char * 0) # Name (variable length)
    ]

# Map inotify events to our event types
EVENT_MAP = {
    IN_CREATE: EventType.CREATED,
    IN_DELETE: EventType.DELETED,
    IN_MODIFY: EventType.MODIFIED,
    IN_MOVED_FROM: EventType.RENAMED,
    IN_MOVED_TO: EventType.RENAMED,
    IN_DELETE_SELF: EventType.DELETED,
    IN_MOVE_SELF: EventType.RENAMED,
    IN_ATTRIB: EventType.MODIFIED
}

class LinuxInotifyWatcher:
    """File system watcher implementation for Linux using inotify."""
    
    def __init__(self, path: str, callback: Callable, recursive: bool = True):
        """
        Initialize the Linux inotify watcher.
        
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
        self._inotify_fd: int = -1
        self._watch_descriptors: Dict[int, str] = {}
        self._cookie_events: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.RLock()
    
    def start(self) -> None:
        """Start watching for file system changes."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Watcher is already running")
            return
            
        # Initialize inotify
        try:
            self._init_inotify()
        except Exception as e:
            logger.error(f"Failed to initialize inotify: {e}")
            raise
            
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
        
        # Clean up
        self._cleanup()
        logger.info(f"Stopped watching directory: {self.path}")
    
    def is_running(self) -> bool:
        """Check if the watcher is running."""
        return self._thread is not None and self._thread.is_alive()
    
    def _init_inotify(self) -> None:
        """Initialize the inotify instance and set up watches."""
        # Load the inotify library
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        
        # Initialize inotify
        self._inotify_fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if self._inotify_fd == -1:
            errno = ctypes.get_errno()
            raise OSError(errno, f"inotify_init1 failed: {os.strerror(errno)}")
        
        # Set up the watch for the root directory
        self._add_watch(self.path, self.recursive)
    
    def _add_watch(self, path: str, recursive: bool) -> None:
        """
        Add a watch for the specified path.
        
        Args:
            path: Path to watch
            recursive: Whether to watch subdirectories
        """
        if not os.path.isdir(path):
            logger.warning(f"Cannot watch non-directory: {path}")
            return
            
        try:
            # Define the inotify_add_watch function
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            inotify_add_watch = libc.inotify_add_watch
            inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            inotify_add_watch.restype = ctypes.c_int
            
            # Add the watch
            mask = (IN_ALL_EVENTS & ~(IN_ACCESS | IN_OPEN | IN_CLOSE_NOWRITE))
            wd = inotify_add_watch(
                self._inotify_fd,
                path.encode('utf-8'),
                mask
            )
            
            if wd == -1:
                errno = ctypes.get_errno()
                logger.warning(f"Failed to add watch for {path}: {os.strerror(errno)}")
                return
                
            # Store the watch descriptor
            with self._lock:
                self._watch_descriptors[wd] = path
            
            logger.debug(f"Added watch for directory: {path} (wd={wd})")
            
            # Recursively add watches for subdirectories if requested
            if recursive:
                try:
                    for entry in os.scandir(path):
                        if entry.is_dir() and not entry.is_symlink():
                            self._add_watch(entry.path, recursive)
                except (OSError, PermissionError) as e:
                    logger.warning(f"Failed to scan directory {path}: {e}")
                    
        except Exception as e:
            logger.error(f"Error adding watch for {path}: {e}", exc_info=True)
    
    def _remove_watch(self, wd: int) -> None:
        """
        Remove a watch by watch descriptor.
        
        Args:
            wd: Watch descriptor to remove
        """
        if wd < 0:
            return
            
        try:
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            inotify_rm_watch = libc.inotify_rm_watch
            inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            inotify_rm_watch.restype = ctypes.c_int
            
            if inotify_rm_watch(self._inotify_fd, wd) == -1:
                errno = ctypes.get_errno()
                logger.warning(f"Failed to remove watch {wd}: {os.strerror(errno)}")
            
            with self._lock:
                if wd in self._watch_descriptors:
                    del self._watch_descriptors[wd]
                    
            logger.debug(f"Removed watch (wd={wd})")
            
        except Exception as e:
            logger.error(f"Error removing watch {wd}: {e}")
    
    def _run(self) -> None:
        """Main watcher loop."""
        try:
            # Buffer for reading events
            buf = bytearray(4096)
            
            while not self._stop_event.is_set():
                try:
                    # Use select to wait for events with a timeout
                    r, _, _ = select.select([self._inotify_fd], [], [], 1.0)
                    
                    if not r:
                        # Timeout, check if we should stop
                        continue
                    
                    # Read the events
                    try:
                        nbytes = os.read(self._inotify_fd, 4096)
                    except (OSError, IOError) as e:
                        if e.errno == 11:  # EAGAIN, no data available
                            continue
                        raise
                    
                    if not nbytes:
                        logger.error("inotify fd closed unexpectedly")
                        break
                    
                    # Process the events
                    offset = 0
                    while offset + 16 <= len(nbytes):  # 16 is the size of inotify_event
                        event = InotifyEvent.from_buffer_copy(nbytes[offset:offset+16])
                        offset += 16
                        
                        # Get the name if present
                        name = None
                        if event.length > 0:
                            name_bytes = nbytes[offset:offset+event.length].rstrip(b'\x00')
                            name = name_bytes.decode('utf-8', errors='replace')
                            offset += event.length
                        
                        # Process the event
                        self._process_event(event.wd, event.mask, event.cookie, name)
                    
                except (OSError, IOError) as e:
                    if e.errno == 4:  # EINTR, interrupted system call
                        continue
                    logger.error(f"Error in inotify event loop: {e}")
                    time.sleep(1)  # Prevent tight loop on errors
                except Exception as e:
                    logger.error(f"Unexpected error in inotify event loop: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on errors
                    
        finally:
            self._cleanup()
    
    def _process_event(self, wd: int, mask: int, cookie: int, name: Optional[str]) -> None:
        """
        Process a single inotify event.
        
        Args:
            wd: Watch descriptor
            mask: Event mask
            cookie: Cookie for related events (e.g., IN_MOVED_FROM/IN_MOVED_TO)
            name: Name of the affected file/directory (relative to watched directory)
        """
        try:
            # Get the path being watched
            with self._lock:
                watch_path = self._watch_descriptors.get(wd)
            
            if not watch_path:
                logger.warning(f"Unknown watch descriptor: {wd}")
                return
            
            # Build the full path
            path = os.path.join(watch_path, name) if name else watch_path
            is_dir = bool(mask & IN_ISDIR)
            
            # Handle directory-specific events
            if is_dir:
                if mask & IN_CREATE and name and self.recursive:
                    # New directory created, add a watch for it
                    self._add_watch(path, self.recursive)
                elif mask & IN_DELETE_SELF or mask & IN_MOVE_SELF:
                    # Watched directory was deleted or moved
                    with self._lock:
                        if wd in self._watch_descriptors:
                            del self._watch_descriptors[wd]
                    return
            
            # Map the event to our event type
            event_type = None
            for event_mask, mapped_type in EVENT_MAP.items():
                if mask & event_mask:
                    event_type = mapped_type
                    break
            
            if not event_type:
                # Unhandled event type
                return
            
            # Handle rename/move events (they come in pairs with the same cookie)
            if mask & (IN_MOVED_FROM | IN_MOVED_TO):
                with self._lock:
                    if cookie in self._cookie_events:
                        # This is the second part of a move event
                        old_event = self._cookie_events.pop(cookie)
                        if mask & IN_MOVED_TO:
                            # We have both parts of the move, emit a RENAMED event
                            self.callback(
                                EventType.RENAMED,
                                old_event['path'],
                                path
                            )
                    else:
                        # This is the first part of a move event, store it
                        self._cookie_events[cookie] = {
                            'path': path,
                            'is_dir': is_dir,
                            'mask': mask
                        }
                return
            
            # For other events, just call the callback
            self.callback(event_type, path)
            
        except Exception as e:
            logger.error(f"Error processing inotify event: {e}", exc_info=True)
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        # Remove all watches
        with self._lock:
            for wd in list(self._watch_descriptors.keys()):
                self._remove_watch(wd)
            
            # Clear any pending cookie events
            self._cookie_events.clear()
        
        # Close the inotify file descriptor
        if hasattr(self, '_inotify_fd') and self._inotify_fd >= 0:
            try:
                os.close(self._inotify_fd)
                self._inotify_fd = -1
            except OSError as e:
                logger.error(f"Error closing inotify file descriptor: {e}")
