"""
File monitoring component for DLP system.
Monitors file system for new/changed files and scans them for sensitive data.
"""
import os
import time
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileSystemMovedEvent

class DLPFileMonitor:
    """Monitors directories for file changes and triggers DLP scans."""
    
    def __init__(self, scan_callback: Callable[[str, bytes], None], 
                 whitelist: List[str] = None, blacklist: List[str] = None):
        """
        Initialize the file monitor.
        
        Args:
            scan_callback: Function to call when a file needs to be scanned
            whitelist: List of file extensions to monitor (if None, monitor all)
            blacklist: List of file extensions to ignore
        """
        self.scan_callback = scan_callback
        self.whitelist = {ext.lower() for ext in (whitelist or [])}
        self.blacklist = {ext.lower() for ext in (blacklist or [])}
        self.observer = Observer()
        self.watched_paths: Dict[str, Set[str]] = {}
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # Track processed files to avoid duplicate scans
        self.processed_files: Dict[str, str] = {}  # path -> hash
    
    def start(self) -> None:
        """Start the file monitoring service."""
        if not self.running:
            self.observer.start()
            self.running = True
            self.logger.info("DLP file monitoring started")
    
    def stop(self) -> None:
        """Stop the file monitoring service."""
        if self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            self.logger.info("DLP file monitoring stopped")
    
    def add_watch_directory(self, path: str, recursive: bool = True) -> None:
        """
        Add a directory to watch for file changes.
        
        Args:
            path: Directory path to watch
            recursive: Whether to watch subdirectories
        """
        try:
            path = os.path.abspath(path)
            if not os.path.isdir(path):
                self.logger.warning(f"Watch path does not exist or is not a directory: {path}")
                return
                
            # Check if already watching this path
            if path in self.watched_paths:
                self.logger.debug(f"Already watching path: {path}")
                return
            
            # Create event handler for this path
            handler = DLPFileHandler(self)
            self.observer.schedule(handler, path, recursive=recursive)
            self.watched_paths[path] = set()
            
            self.logger.info(f"Added DLP watch on directory: {path} (recursive={recursive})")
            
            # Initial scan of existing files
            if recursive:
                for root, _, files in os.walk(path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        self._process_file(filepath)
            else:
                for entry in os.scandir(path):
                    if entry.is_file():
                        self._process_file(entry.path)
                        
        except Exception as e:
            self.logger.error(f"Error adding watch directory {path}: {e}", exc_info=True)
    
    def remove_watch_directory(self, path: str) -> None:
        """
        Remove a directory from being watched.
        
        Args:
            path: Directory path to stop watching
        """
        path = os.path.abspath(path)
        if path in self.watched_paths:
            # We can't easily remove a watch in watchdog, so we'll just stop tracking it
            del self.watched_paths[path]
            self.logger.info(f"Removed DLP watch on directory: {path}")
    
    def _process_file(self, filepath: str) -> None:
        """Process a file for DLP scanning."""
        try:
            # Skip directories
            if not os.path.isfile(filepath):
                return
                
            # Check file extension against whitelist/blacklist
            if not self._should_scan_file(filepath):
                return
            
            # Skip files that haven't changed since last scan
            file_hash = self._get_file_hash(filepath)
            if filepath in self.processed_files and self.processed_files[filepath] == file_hash:
                return
            
            # Read file content
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
            except (IOError, PermissionError) as e:
                self.logger.warning(f"Could not read file {filepath}: {e}")
                return
            
            # Call the scan callback
            self.scan_callback(filepath, content)
            
            # Update processed files cache
            self.processed_files[filepath] = file_hash
            
            # Limit the size of the cache
            if len(self.processed_files) > 10000:  # Keep last 10,000 files
                self.processed_files.pop(next(iter(self.processed_files)))
                
        except Exception as e:
            self.logger.error(f"Error processing file {filepath}: {e}", exc_info=True)
    
    def _should_scan_file(self, filepath: str) -> bool:
        """Determine if a file should be scanned based on its extension."""
        ext = Path(filepath).suffix.lower()
        
        # Skip files with no extension
        if not ext:
            return False
            
        # Remove the leading dot
        ext = ext[1:]
        
        # Check blacklist first
        if self.blacklist and ext in self.blacklist:
            return False
            
        # If whitelist is specified, only allow those extensions
        if self.whitelist and ext not in self.whitelist:
            return False
            
        return True
    
    @staticmethod
    def _get_file_hash(filepath: str, chunk_size: int = 8192) -> str:
        """Calculate a hash of the file content."""
        hasher = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError):
            return ""


class DLPFileHandler(FileSystemEventHandler):
    """Handles file system events for DLP monitoring."""
    
    def __init__(self, monitor: 'DLPFileMonitor'):
        self.monitor = monitor
        self.logger = logging.getLogger(f"{__name__}.DLPFileHandler")
    
    def on_created(self, event: FileSystemEvent) -> None:
        """Called when a file or directory is created."""
        if not event.is_directory:
            self.monitor._process_file(event.src_path)
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """Called when a file or directory is modified."""
        if not event.is_directory:
            self.monitor._process_file(event.src_path)
    
    def on_moved(self, event: FileSystemMovedEvent) -> None:
        """Called when a file or directory is moved/renamed."""
        if not event.is_directory:
            # Process the new file
            self.monitor._process_file(event.dest_path)
            
            # Remove the old path from processed files
            if event.src_path in self.monitor.processed_files:
                del self.monitor.processed_files[event.src_path]
