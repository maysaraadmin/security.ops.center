"""
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
from queue import Queue

logger = logging.getLogger('fim.monitors')

class BaseMonitor(threading.Thread):
    """Base class for all monitoring implementations."""
    
    def __init__(self, target_path: str, engine: Any):
        """
        Initialize the monitor.
        
        Args:
            target_path: Path to monitor (file, directory, or registry key)
            engine: Reference to the FIM engine
        """
        super().__init__(daemon=True)
        self.target_path = target_path
        self.engine = engine
        self._stop_event = threading.Event()
        
    def stop(self) -> None:
        """Stop the monitoring thread."""
        self._stop_event.set()
        
    def run(self) -> None:
        """Main monitoring loop."""
        raise NotImplementedError("Subclasses must implement run()")

class FileMonitor(BaseMonitor):
    """Monitors a single file for changes."""
    
    def __init__(self, file_path: str, engine: Any):
        """
        Initialize file monitoring.
        
        Args:
            file_path: Path to the file to monitor
            engine: Reference to the FIM engine
        """
        super().__init__(file_path, engine)
        self.file_path = Path(file_path)
        
    def run(self) -> None:
        """Monitor the file for changes."""
        try:
            # Initial state
            last_modified = self.file_path.stat().st_mtime
            
            while not self._stop_event.is_set():
                try:
                    current_modified = self.file_path.stat().st_mtime
                    if current_modified > last_modified:
                        # File was modified
                        self.engine.handle_event(
                            file_path=str(self.file_path),
                            event_type='modified',
                            timestamp=current_modified
                        )
                        last_modified = current_modified
                except FileNotFoundError:
                    # File was deleted
                    self.engine.handle_event(
                        file_path=str(self.file_path),
                        event_type='deleted',
                        timestamp=time.time()
                    )
                    break
                
                time.sleep(self.engine.scan_interval)
                
        except Exception as e:
            logger.error(f"Error monitoring file {self.file_path}: {e}")
            raise

class DirectoryMonitor(BaseMonitor):
    """Monitors a directory and its subdirectories for changes."""
    
    def __init__(self, dir_path: str, engine: Any, recursive: bool = True):
        """
        Initialize directory monitoring.
        
        Args:
            dir_path: Path to the directory to monitor
            engine: Reference to the FIM engine
            recursive: If True, monitor subdirectories as well
        """
        super().__init__(dir_path, engine)
        self.dir_path = Path(dir_path)
        self.recursive = recursive
        self._watchers: Dict[str, Any] = {}
        
    def run(self) -> None:
        """Monitor the directory for changes."""
        try:
            # Initial scan
            self._scan_directory()
            
            # Main monitoring loop
            while not self._stop_event.is_set():
                try:
                    self._check_for_changes()
                    time.sleep(self.engine.scan_interval)
                except Exception as e:
                    logger.error(f"Error in directory monitor: {e}")
                    time.sleep(5)  # Prevent tight loop on errors
                    
        except Exception as e:
            logger.error(f"Error monitoring directory {self.dir_path}: {e}")
            raise
    
    def _scan_directory(self) -> None:
        """Scan the directory and set up initial state."""
        if not self.dir_path.exists():
            logger.warning(f"Directory {self.dir_path} does not exist")
            return
            
        for item in self.dir_path.iterdir():
            if item.is_file():
                self._watch_file(item)
            elif item.is_dir() and self.recursive:
                self._watch_directory(item)
    
    def _watch_file(self, file_path: Path) -> None:
        """Start watching a file."""
        if str(file_path) not in self._watchers:
            self._watchers[str(file_path)] = {
                'path': file_path,
                'last_modified': file_path.stat().st_mtime,
                'size': file_path.stat().st_size
            }
    
    def _watch_directory(self, dir_path: Path) -> None:
        """Start watching a directory."""
        if str(dir_path) not in self._watchers:
            self._watchers[str(dir_path)] = {
                'path': dir_path,
                'last_modified': dir_path.stat().st_mtime,
                'is_dir': True
            }
            
            # Recursively add contents if needed
            if self.recursive:
                try:
                    for item in dir_path.iterdir():
                        if item.is_file():
                            self._watch_file(item)
                        elif item.is_dir():
                            self._watch_directory(item)
                except PermissionError:
                    logger.warning(f"Permission denied accessing {dir_path}")
    
    def _check_for_changes(self) -> None:
        """Check for changes in the monitored directory."""
        # Check existing files/directories
        for path_str, info in list(self._watchers.items()):
            try:
                path = info['path']
                
                if not path.exists():
                    # Item was deleted
                    self.engine.handle_event(
                        file_path=str(path),
                        event_type='deleted',
                        timestamp=time.time()
                    )
                    del self._watchers[path_str]
                    continue
                    
                current_modified = path.stat().st_mtime
                
                if 'is_dir' in info and info['is_dir']:
                    # Directory handling
                    if current_modified > info['last_modified']:
                        self.engine.handle_event(
                            file_path=str(path),
                            event_type='modified',
                            timestamp=current_modified
                        )
                        info['last_modified'] = current_modified
                else:
                    # File handling
                    current_size = path.stat().st_size
                    
                    if (current_modified > info['last_modified'] or 
                        current_size != info['size']):
                        # File was modified
                        self.engine.handle_event(
                            file_path=str(path),
                            event_type='modified',
                            timestamp=current_modified
                        )
                        info['last_modified'] = current_modified
                        info['size'] = current_size
                        
            except Exception as e:
                logger.error(f"Error checking {path_str}: {e}")
                
        # Check for new files/directories
        try:
            for item in self.dir_path.iterdir():
                if str(item) not in self._watchers:
                    if item.is_file():
                        self._watch_file(item)
                        self.engine.handle_event(
                            file_path=str(item),
                            event_type='created',
                            timestamp=item.stat().st_mtime
                        )
                    elif item.is_dir() and self.recursive:
                        self._watch_directory(item)
                        self.engine.handle_event(
                            file_path=str(item),
                            event_type='created',
                            timestamp=item.stat().st_mtime,
                            is_dir=True
                        )
        except PermissionError as e:
            logger.warning(f"Permission error scanning directory: {e}")

class RegistryMonitor(BaseMonitor):
    """Monitors Windows registry keys for changes."""
    
    def __init__(self, key_path: str, engine: Any, watch_subkeys: bool = True):
        """
        Initialize registry monitoring.
        
        Args:
            key_path: Full path to the registry key to monitor (e.g., 'HKEY_LOCAL_MACHINE\Software')
            engine: Reference to the FIM engine
            watch_subkeys: If True, monitor all subkeys (default: True)
        """
        super().__init__(key_path, engine)
        self.watch_subkeys = watch_subkeys
        self._watchers: Dict[str, threading.Thread] = {}
    
    def run(self) -> None:
        """Monitor the registry key for changes."""
        try:
            # This is a placeholder - actual implementation would use Windows API
            # to monitor registry changes
            logger.warning("Registry monitoring is not fully implemented")
            
            while not self._stop_event.is_set():
                time.sleep(self.engine.scan_interval)
                
        except Exception as e:
            logger.error(f"Error monitoring registry: {e}")
            raise
    
    def stop(self) -> None:
        """Stop monitoring the registry."""
        super().stop()
        for watcher in self._watchers.values():
            watcher.stop()
        self._watchers.clear()

# For backward compatibility
BaseMonitor = BaseMonitor
