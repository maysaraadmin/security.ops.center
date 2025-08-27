"""
Log Collector component for the SIEM.

This module implements a log collector that monitors specified log files
and forwards log entries to the SIEM for processing.
"""

import os
import time
import queue
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass

# Configure logger
logger = logging.getLogger('siem.components.log_collector')

@dataclass
class LogFile:
    """Represents a log file being monitored."""
    path: str
    inode: int
    position: int = 0
    last_modified: float = 0

class LogCollector:
    """
    A component that collects logs from various sources and forwards them
    to the SIEM for processing.
    """
    
    def __init__(self, config: Dict[str, Any], event_bus: Any):
        """
        Initialize the LogCollector.
        
        Args:
            config: Configuration dictionary for the log collector
            event_bus: Event bus for publishing collected logs
        """
        self.config = config
        self.event_bus = event_bus
        self.running = False
        self.thread = None
        self.log_files: Dict[str, LogFile] = {}
        self.file_patterns = self.config.get('paths', ['/var/log/**/*.log'])
        self.poll_interval = self.config.get('poll_interval', 5)
        self.processed_files: Set[str] = set()
        
        # For thread safety
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        
        logger.info("LogCollector initialized")
    
    def start(self) -> None:
        """Start the log collector."""
        if self.running:
            logger.warning("LogCollector is already running")
            return
            
        logger.info("Starting LogCollector...")
        
        # Initial discovery of log files
        self._discover_log_files()
        
        if not self.log_files:
            logger.warning("No log files found matching the patterns: %s", self.file_patterns)
        else:
            logger.info("Monitoring %d log files: %s", 
                      len(self.log_files), 
                      ', '.join(os.path.basename(path) for path in self.log_files.keys()))
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True, name="LogCollector")
        self.thread.start()
        logger.info("LogCollector started")
    
    def stop(self) -> None:
        """Stop the log collector."""
        if not self.running:
            return
            
        logger.info("Stopping LogCollector...")
        self.running = False
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
            
        logger.info("LogCollector stopped")
    
    def _run(self) -> None:
        """Main loop for the log collector thread."""
        while self.running:
            try:
                self._discover_log_files()
                self._process_log_files()
                time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Error in LogCollector main loop: {e}", exc_info=True)
                time.sleep(5)  # Prevent tight loop on error
    
    def _discover_log_files(self) -> None:
        """Discover log files matching the configured patterns."""
        from glob import glob
        
        discovered_files = set()
        
        # Find all files matching the patterns
        for pattern in self.file_patterns:
            try:
                # Convert to absolute path if it's a relative path
                if not os.path.isabs(pattern):
                    pattern = os.path.abspath(pattern)
                    
                # Ensure forward slashes for glob (using raw string to avoid escape issues)
                pattern = pattern.replace('\\', '/')
                logger.debug("Searching for log files matching: %s", pattern)
                
                for file_path in glob(pattern, recursive=True):
                    file_path = os.path.abspath(file_path)
                    if os.path.isfile(file_path):
                        discovered_files.add(file_path)
                        
            except Exception as e:
                logger.error("Error processing pattern '%s': %s", pattern, str(e), exc_info=True)
        
        # Add new files
        for file_path in discovered_files:
            if file_path not in self.log_files:
                try:
                    self._add_log_file(file_path)
                except Exception as e:
                    logger.error(f"Error adding log file {file_path}: {e}")
        
        # Remove deleted files
        for file_path in list(self.log_files.keys()):
            if file_path not in discovered_files:
                logger.debug(f"Removing deleted log file: {file_path}")
                del self.log_files[file_path]
    
    def _add_log_file(self, file_path: str) -> None:
        """Add a log file to be monitored."""
        try:
            stat = os.stat(file_path)
            log_file = LogFile(
                path=file_path,
                inode=stat.st_ino,
                position=0,
                last_modified=stat.st_mtime
            )
            
            # Start reading from the end of the file if it's not new
            if stat.st_size > 0 and not self.config.get('read_from_beginning', False):
                log_file.position = stat.st_size
            
            self.log_files[file_path] = log_file
            logger.info(f"Added log file: {file_path}")
            
        except Exception as e:
            logger.error(f"Error adding log file {file_path}: {e}")
            raise
    
    def _process_log_files(self) -> None:
        """Process all monitored log files for new entries."""
        for log_file in list(self.log_files.values()):
            if not self.running:
                break
                
            try:
                self._process_log_file(log_file)
            except Exception as e:
                logger.error(f"Error processing log file {log_file.path}: {e}", exc_info=True)
    
    def _process_log_file(self, log_file: LogFile) -> None:
        """Process a single log file for new entries."""
        try:
            # Check if file has been rotated (inode changed) or modified
            try:
                stat = os.stat(log_file.path)
                
                # If inode changed, the file was rotated
                if stat.st_ino != log_file.inode:
                    logger.info("Detected rotation for log file: %s (inode changed: %s -> %s)", 
                              log_file.path, log_file.inode, stat.st_ino)
                    # Save the old log file
                    old_log_file = log_file
                    # Add the new file
                    self._add_log_file(log_file.path)
                    # Update the position to the old file's size
                    if old_log_file.path in self.log_files:
                        self.log_files[old_log_file.path].position = old_log_file.position
                    return
                    
                # If file was truncated, reset position
                if stat.st_size < log_file.position:
                    logger.info("Log file was truncated: %s (size: %d -> %d)", 
                              log_file.path, log_file.position, stat.st_size)
                    log_file.position = 0
                
                log_file.last_modified = stat.st_mtime
                
            except FileNotFoundError:
                logger.warning(f"Log file not found (may have been deleted): {log_file.path}")
                if log_file.path in self.log_files:
                    del self.log_files[log_file.path]
                return
            
            # Read new lines if file has grown
            if stat.st_size > log_file.position:
                with open(log_file.path, 'r', errors='replace') as f:
                    # Seek to the last known position
                    f.seek(log_file.position)
                    
                    # Read and process new lines
                    for line in f:
                        self._process_log_line(line.strip(), log_file.path)
                    
                    # Update the position
                    log_file.position = f.tell()
                    
        except Exception as e:
            logger.error(f"Error reading log file {log_file.path}: {e}", exc_info=True)
    
    def _process_log_line(self, line: str, source: str) -> None:
        """Process a single log line."""
        if not line or not line.strip():
            return
            
        try:
            # Clean up the line
            line = line.strip()
            
            # Skip empty lines
            if not line:
                return
                
            # Create a log event with additional metadata
            log_event = {
                'timestamp': time.time(),
                'source': source,
                'message': line,
                'type': 'log',
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'collector': 'log_collector',
                'pid': os.getpid()
            }
            
            # Publish the event
            self.event_bus.publish('log_event', log_event)
            
            # Log at debug level to avoid flooding the logs
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Published log event from %s: %s", source, line[:200] + ('...' if len(line) > 200 else ''))
                
        except Exception as e:
            logger.error("Error processing log line from %s: %s", source, str(e), exc_info=True)


def create_component(config: Dict[str, Any], event_bus: Any) -> LogCollector:
    """
    Factory function to create a LogCollector instance.
    
    Args:
        config: Component configuration
        event_bus: Event bus for publishing events
        
    Returns:
        LogCollector: Configured LogCollector instance
    """
    return LogCollector(config, event_bus)
