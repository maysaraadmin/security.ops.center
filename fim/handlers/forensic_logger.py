"""
Forensic Logging Handler for File Integrity Monitoring

This module provides a handler for detailed forensic logging of file system events,
including user/process information and change details for compliance and investigation.
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Union, TextIO
from pathlib import Path

from ..core import FileEvent, EventType, EventHandler

class ForensicLogger(EventHandler):
    """
    Logs detailed forensic information about file system events for compliance
    and investigation purposes.
    
    Logs include:
    - Who made the change (user, process, session)
    - What was changed (file content, permissions, attributes)
    - When it happened (precise timestamp)
    - Additional context (process path, command line, etc.)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the forensic logger.
        
        Args:
            config: Configuration dictionary with the following keys:
                - log_file: Path to the log file (default: 'fim_forensic.log')
                - max_size: Maximum log file size in MB before rotation (default: 10)
                - backup_count: Number of backup logs to keep (default: 5)
                - format: Log format string
        """
        super().__init__(config or {})
        self.log_file = Path(self.config.get('log_file', 'fim_forensic.log'))
        self.max_size = self.config.get('max_size', 10) * 1024 * 1024  # Convert MB to bytes
        self.backup_count = self.config.get('backup_count', 5)
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure the logging handler with rotation."""
        # Create log directory if it doesn't exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Set up the logger
        self.logger = logging.getLogger('fim.forensic')
        self.logger.setLevel(logging.INFO)
        
        # Remove any existing handlers to avoid duplicate logs
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            self.config.get('format', 
                          '%(asctime)s - %(levelname)s - %(message)s')
        )
        
        # Add file handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=self.max_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def handle(self, event: FileEvent) -> None:
        """
        Process a file system event and log forensic details.
        
        Args:
            event: The file system event to log
        """
        try:
            # Prepare the log entry
            log_entry = self._prepare_log_entry(event)
            
            # Log the event
            self.logger.info(json.dumps(log_entry, ensure_ascii=False))
            
        except Exception as e:
            logging.error(f"Error in forensic logging: {e}", exc_info=True)
    
    def _prepare_log_entry(self, event: FileEvent) -> Dict[str, Any]:
        """
        Prepare a log entry with forensic details.
        
        Args:
            event: The file system event
            
        Returns:
            Dictionary containing forensic log entry
        """
        # Get basic event information
        entry = {
            'timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
            'event_type': event.event_type.name,
            'path': event.src_path,
            'user': event.user or 'SYSTEM',
            'process': {
                'name': event.process,
                'path': event.process_path,
                'command_line': event.process_cmdline,
                'session_id': event.session_id
            },
            'file': {
                'is_directory': event.is_directory,
                'size': event.file_size,
                'last_modified': event.last_modified and 
                               datetime.fromtimestamp(event.last_modified).isoformat(),
                'checksum': event.checksum,
                'metadata': event.metadata
            },
            'change_details': event.change_details
        }
        
        # Add destination path for rename events
        if event.event_type == EventType.RENAMED and event.dest_path:
            entry['destination_path'] = event.dest_path
        
        # Clean up None values
        return self._clean_dict(entry)
    
    def _clean_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively remove None values from a dictionary."""
        if not isinstance(d, dict):
            return d
            
        result = {}
        for k, v in d.items():
            if isinstance(v, dict):
                cleaned = self._clean_dict(v)
                if cleaned:  # Only add non-empty dicts
                    result[k] = cleaned
            elif v is not None and v != '':
                result[k] = v
        return result

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(log_file='{self.log_file}')"
