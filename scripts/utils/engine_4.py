"""
FIM Engine Module

This module provides the main File Integrity Monitoring (FIM) engine that integrates
all components for monitoring, baselining, and alerting on file system changes.
"""

import os
import time
import logging
import threading
from typing import Dict, List, Optional, Set, Callable, Any, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json

from .monitor import FileMonitor, FileEvent, EventType
from .baseline import BaselineManager, FileInfo

logger = logging.getLogger('fim.engine')

@dataclass
class FIMEvent:
    """Represents a file integrity monitoring event with additional context."""
    event_type: EventType
    path: str
    timestamp: float
    is_directory: bool = False
    dest_path: Optional[str] = None
    file_info: Optional[FileInfo] = None
    baseline_info: Optional[FileInfo] = None
    diff: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        return {
            'event_type': self.event_type.name,
            'path': self.path,
            'dest_path': self.dest_path,
            'is_directory': self.is_directory,
            'timestamp': self.timestamp,
            'file_info': self.file_info.to_dict() if self.file_info else None,
            'baseline_info': self.baseline_info.to_dict() if self.baseline_info else None,
            'diff': self.diff,
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Convert the event to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

class FIMEngine:
    """Main File Integrity Monitoring engine."""
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        baseline_file: Optional[str] = None,
        alert_callback: Optional[Callable[[FIMEvent], None]] = None
    ):
        """Initialize the FIM engine."""
        self.config = config or {}
        self.baseline_file = baseline_file
        self.alert_callback = alert_callback
        
        # Initialize components
        self.monitor = FileMonitor()
        self.baseline_manager = BaselineManager(baseline_file)
        
        # State
        self.running = False
        self._thread = None
        self._stop_event = threading.Event()
        
        # Configure from config
        self._configure_from_config()
        
        # Register event handlers
        self.monitor.add_callback(self._handle_file_event)
    
    def _configure_from_config(self) -> None:
        """Configure the engine from the provided config."""
        for pattern in self.config.get('ignore_patterns', []):
            self.baseline_manager.add_ignore_pattern(pattern)
    
    def start(self) -> None:
        """Start the FIM engine."""
        if self.running:
            logger.warning("FIM engine is already running")
            return
            
        # Load baseline if it exists
        if self.baseline_file and os.path.isfile(self.baseline_file):
            try:
                self.baseline_manager.load_baseline(self.baseline_file)
                logger.info(f"Loaded baseline from {self.baseline_file}")
            except Exception as e:
                logger.error(f"Failed to load baseline: {e}")
        
        # Start monitoring
        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        
        logger.info("FIM engine started")
    
    def stop(self) -> None:
        """Stop the FIM engine."""
        if not self.running:
            return
            
        logger.info("Stopping FIM engine...")
        self.running = False
        self._stop_event.set()
        
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        
        logger.info("FIM engine stopped")
    
    def _run(self) -> None:
        """Main monitoring loop."""
        self.monitor.start()
        
        try:
            while not self._stop_event.is_set():
                self.monitor.process_events(1.0)
                self._periodic_tasks()
        except Exception as e:
            logger.error(f"Error in FIM engine: {e}", exc_info=True)
        finally:
            self.monitor.stop()
    
    def _periodic_tasks(self) -> None:
        """Perform periodic tasks like integrity checks."""
        if self.config.get('periodic_scan_interval', 0) > 0:
            last_scan = getattr(self, '_last_scan_time', 0)
            now = time.time()
            
            if now - last_scan >= self.config['periodic_scan_interval'] * 3600:
                self._run_integrity_scan()
                self._last_scan_time = now
    
    def _handle_file_event(self, event: FileEvent) -> None:
        """Handle a file system event."""
        try:
            fim_event = FIMEvent(
                event_type=event.event_type,
                path=event.src_path,
                dest_path=event.dest_path,
                is_directory=event.is_directory,
                timestamp=event.timestamp
            )
            
            if os.path.exists(event.src_path):
                file_info = self.baseline_manager._process_file(event.src_path)
                if file_info:
                    fim_event.file_info = file_info
                    
                    if event.src_path in self.baseline_manager.baseline:
                        baseline_info = self.baseline_manager.baseline[event.src_path]
                        fim_event.baseline_info = baseline_info
                        
                        if file_info.hash_value != baseline_info.hash_value:
                            fim_event.diff = {
                                'size': file_info.size - baseline_info.size,
                                'mtime': file_info.mtime - baseline_info.mtime,
                                'hash_differs': True
                            }
            
            self._handle_fim_event(fim_event)
            
        except Exception as e:
            logger.error(f"Error handling file event: {e}", exc_info=True)
    
    def _handle_fim_event(self, event: FIMEvent) -> None:
        """Handle a FIM event."""
        logger.info(f"FIM Event: {event.event_type.name} - {event.path}")
        
        if self.alert_callback:
            try:
                self.alert_callback(event)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}", exc_info=True)
    
    def create_baseline(self, output_file: Optional[str] = None) -> str:
        """Create a new baseline of monitored files."""
        if not output_file and not self.baseline_file:
            raise ValueError("No output file specified")
        
        output_file = output_file or self.baseline_file
        paths = [str(p) for p in self.monitor.paths]
        self.baseline_manager.create_baseline(paths)
        return self.baseline_manager.save_baseline(output_file)
    
    def verify_baseline(self, report_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify the current system against the loaded baseline."""
        return self.baseline_manager.verify_baseline(report_file=report_file)

def create_default_fim_engine(
    watch_paths: List[str],
    config: Optional[Dict[str, Any]] = None,
    baseline_file: Optional[str] = None,
    alert_callback: Optional[Callable[[FIMEvent], None]] = None
) -> FIMEngine:
    """Create a pre-configured FIM engine with sensible defaults."""
    default_config = {
        'periodic_scan_interval': 24,  # hours
        'ignore_patterns': [
            '*.log', '*.tmp', '*.swp', '*.bak', '*.backup',
            '*.pyc', '*.pyo', '__pycache__', '.git', '.svn',
            '*.swo', '*.swn', '*.swm', '*.swl'
        ]
    }
    
    if config:
        default_config.update(config)
    
    engine = FIMEngine(
        config=default_config,
        baseline_file=baseline_file,
        alert_callback=alert_callback
    )
    
    for path in watch_paths:
        engine.monitor.paths.append(Path(path).resolve())
    
    return engine
