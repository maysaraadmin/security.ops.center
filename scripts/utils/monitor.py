"""
File Integrity Monitor - Monitors files for changes and verifies their integrity.
"""
import os
import time
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any, Tuple
from queue import Queue, Empty
from dataclasses import dataclass, asdict
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileSystemMovedEvent

from .integrity_checker import IntegrityChecker, FileIntegrityRecord

@dataclass
class FIMEvent:
    """Represents a file integrity monitoring event."""
    timestamp: float
    event_type: str  # 'created', 'modified', 'deleted', 'moved', 'integrity_violation'
    path: str
    details: Dict[str, Any]
    baseline: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert the event to a dictionary."""
        result = asdict(self)
        result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))
        return result

class FIMEventHandler(FileSystemEventHandler):
    """Handles file system events for FIM monitoring."""
    
    def __init__(self, callback: Callable[[FIMEvent], None], 
                 checker: IntegrityChecker,
                 baselines: Dict[str, FileIntegrityRecord]):
        """
        Initialize the event handler.
        
        Args:
            callback: Function to call when an event occurs
            checker: IntegrityChecker instance
            baselines: Dictionary of file paths to baseline records
        """
        super().__init__()
        self.callback = callback
        self.checker = checker
        self.baselines = baselines
        self.logger = logging.getLogger(f"{__name__}.FIMEventHandler")
    
    def on_created(self, event: FileSystemEvent) -> None:
        """Called when a file or directory is created."""
        if event.is_directory:
            return
            
        path = Path(event.src_path).resolve()
        self.logger.debug(f"File created: {path}")
        
        # If we have a baseline for this path, it's a violation (file was recreated)
        if str(path) in self.baselines:
            self._handle_integrity_violation(
                path,
                "File was recreated",
                self.baselines[str(path)]
            )
        else:
            # New file, create an event
            event = FIMEvent(
                timestamp=time.time(),
                event_type='created',
                path=str(path),
                details={
                    'size': path.stat().st_size if path.exists() else 0
                }
            )
            self.callback(event)
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """Called when a file or directory is modified."""
        if event.is_directory:
            return
            
        path = Path(event.src_path).resolve()
        self.logger.debug(f"File modified: {path}")
        
        # Check if we're monitoring this file
        if str(path) in self.baselines:
            baseline = self.baselines[str(path)]
            is_ok, result = self.checker.verify_file(baseline)
            
            if not is_ok:
                self._handle_integrity_violation(path, "File modified", baseline, result)
    
    def on_deleted(self, event: FileSystemEvent) -> None:
        """Called when a file or directory is deleted."""
        if event.is_directory:
            return
            
        path = Path(event.src_path).resolve()
        self.logger.debug(f"File deleted: {path}")
        
        # If we were monitoring this file, it's a violation
        if str(path) in self.baselines:
            self._handle_integrity_violation(
                path,
                "File was deleted",
                self.baselines[str(path)]
            )
    
    def on_moved(self, event: FileSystemMovedEvent) -> None:
        """Called when a file or directory is moved/renamed."""
        if event.is_directory:
            return
            
        src_path = Path(event.src_path).resolve()
        dest_path = Path(event.dest_path).resolve()
        self.logger.debug(f"File moved: {src_path} -> {dest_path}")
        
        # If we were monitoring the source path, update our baseline
        if str(src_path) in self.baselines:
            baseline = self.baselines.pop(str(src_path))
            baseline.file_path = str(dest_path)
            self.baselines[str(dest_path)] = baseline
            
            # Create a moved event
            event = FIMEvent(
                timestamp=time.time(),
                event_type='moved',
                path=str(dest_path),
                details={
                    'source_path': str(src_path)
                },
                baseline=baseline.to_dict()
            )
            self.callback(event)
    
    def _handle_integrity_violation(self, path: Path, reason: str, 
                                  baseline: FileIntegrityRecord,
                                  verification_result: Dict = None) -> None:
        """Handle an integrity violation."""
        self.logger.warning(f"Integrity violation detected for {path}: {reason}")
        
        event = FIMEvent(
            timestamp=time.time(),
            event_type='integrity_violation',
            path=str(path),
            details={
                'reason': reason,
                'verification_result': verification_result or {}
            },
            baseline=baseline.to_dict()
        )
        self.callback(event)

class FIMMonitor:
    """Monitors files for changes and verifies their integrity."""
    
    def __init__(self, baselines: Dict[str, FileIntegrityRecord] = None):
        """
        Initialize the FIM monitor.
        
        Args:
            baselines: Dictionary of file paths to baseline records
        """
        self.baselines = baselines or {}
        self.checker = IntegrityChecker()
        self.observer = None
        self.event_handlers = []
        self.event_queue = Queue()
        self.running = False
        self.worker_thread = None
        self.logger = logging.getLogger(__name__)
    
    def add_baseline(self, record: FileIntegrityRecord) -> None:
        """Add a baseline record to monitor."""
        self.baselines[record.file_path] = record
    
    def remove_baseline(self, file_path: str) -> bool:
        """Remove a baseline record by file path."""
        if file_path in self.baselines:
            del self.baselines[file_path]
            return True
        return False
    
    def start(self) -> None:
        """Start the FIM monitor."""
        if self.running:
            self.logger.warning("FIM monitor is already running")
            return
        
        self.running = True
        
        # Start the event processing thread
        self.worker_thread = threading.Thread(
            target=self._process_events,
            name="FIMEventProcessor",
            daemon=True
        )
        self.worker_thread.start()
        
        # Start the file system observer
        self.observer = Observer()
        
        # Group files by parent directory for more efficient watching
        dirs_to_watch = {}
        for path in self.baselines.keys():
            path_obj = Path(path)
            if path_obj.exists():
                parent = str(path_obj.parent)
                if parent not in dirs_to_watch:
                    dirs_to_watch[parent] = []
                dirs_to_watch[parent].append(path)
        
        # Start watching each directory
        for directory, files in dirs_to_watch.items():
            try:
                # Create an event handler for this directory
                handler = FIMEventHandler(
                    callback=self._queue_event,
                    checker=self.checker,
                    baselines={path: self.baselines[path] for path in files}
                )
                self.event_handlers.append(handler)
                
                # Start watching
                self.observer.schedule(handler, directory, recursive=False)
                self.logger.info(f"Watching directory for changes: {directory}")
                
            except Exception as e:
                self.logger.error(f"Failed to watch directory {directory}: {e}")
        
        # Start the observer
        self.observer.start()
        self.logger.info("FIM monitor started")
    
    def stop(self) -> None:
        """Stop the FIM monitor."""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the observer
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        
        # Clear event handlers
        self.event_handlers.clear()
        
        # Wait for the worker thread to finish
        if self.worker_thread and self.worker_thread.is_alive():
            # Put a sentinel value in the queue to wake up the worker
            self.event_queue.put(None)
            self.worker_thread.join(timeout=5.0)
            
            if self.worker_thread.is_alive():
                self.logger.warning("Worker thread did not stop gracefully")
        
        self.logger.info("FIM monitor stopped")
    
    def _queue_event(self, event: FIMEvent) -> None:
        """Add an event to the processing queue."""
        self.event_queue.put(event)
    
    def _process_events(self) -> None:
        """Process events from the queue."""
        self.logger.debug("FIM event processor started")
        
        while self.running:
            try:
                # Wait for an event with a timeout to allow checking self.running
                try:
                    event = self.event_queue.get(timeout=1.0)
                except Empty:
                    continue
                
                # Check for sentinel value
                if event is None:
                    break
                
                # Process the event
                self._handle_event(event)
                
            except Exception as e:
                self.logger.error(f"Error processing FIM event: {e}", exc_info=True)
        
        self.logger.debug("FIM event processor stopped")
    
    def _handle_event(self, event: FIMEvent) -> None:
        """Handle a FIM event."""
        # This is a placeholder. In a real implementation, you would:
        # 1. Log the event
        # 2. Trigger alerts if needed
        # 3. Update the UI (if running in a GUI)
        # 4. Take any configured actions
        
        self.logger.info(f"FIM event: {event.event_type} - {event.path}")
        
        # Example: For integrity violations, we might want to take action
        if event.event_type == 'integrity_violation':
            self._handle_integrity_violation(event)
    
    def _handle_integrity_violation(self, event: FIMEvent) -> None:
        """Handle an integrity violation event."""
        # Log the violation
        self.logger.warning(
            f"Integrity violation detected for {event.path}: "
            f"{event.details.get('reason', 'Unknown reason')}"
        )
        
        # In a real implementation, you might:
        # 1. Send an alert
        # 2. Quarantine the file
        # 3. Restore from backup
        # 4. Notify an administrator
        
        # For now, we'll just log the details
        if 'verification_result' in event.details:
            result = event.details['verification_result']
            self.logger.debug(f"Verification result: {result}")
    
    def verify_all(self) -> List[Tuple[bool, str, Dict]]:
        """
        Verify all monitored files.
        
        Returns:
            List of (is_ok, file_path, result_dict) tuples
        """
        results = []
        
        for path, baseline in list(self.baselines.items()):
            try:
                is_ok, result = self.checker.verify_file(baseline)
                results.append((is_ok, path, result))
                
                if not is_ok:
                    self._handle_integrity_violation(FIMEvent(
                        timestamp=time.time(),
                        event_type='integrity_violation',
                        path=path,
                        details={
                            'reason': 'Periodic verification failed',
                            'verification_result': result
                        },
                        baseline=baseline.to_dict()
                    ))
                    
            except Exception as e:
                self.logger.error(f"Error verifying {path}: {e}")
                results.append((False, path, {"error": str(e)}))
        
        return results
    
    def save_baselines(self, file_path: str) -> bool:
        """
        Save baselines to a JSON file.
        
        Args:
            file_path: Path to save the baselines to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'w') as f:
                data = {
                    'version': '1.0',
                    'timestamp': time.time(),
                    'baselines': [
                        {'file_path': path, **record.to_dict()}
                        for path, record in self.baselines.items()
                    ]
                }
                json.dump(data, f, indent=2)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save baselines to {file_path}: {e}")
            return False
    
    @classmethod
    def load_baselines(cls, file_path: str) -> Optional[Dict[str, FileIntegrityRecord]]:
        """
        Load baselines from a JSON file.
        
        Args:
            file_path: Path to load the baselines from
            
        Returns:
            Dictionary of file paths to FileIntegrityRecord objects, or None on error
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            baselines = {}
            for item in data.get('baselines', []):
                record = FileIntegrityRecord.from_dict(item)
                baselines[record.file_path] = record
                
            return baselines
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to load baselines from {file_path}: {e}")
            return None
