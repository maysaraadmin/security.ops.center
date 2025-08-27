"""
Base collector class for log collection in SIEM.
"""
import abc
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

class BaseCollector(abc.ABC):
    """Abstract base class for all log collectors."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the collector with configuration.
        
        Args:
            config: Configuration dictionary for the collector
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"siem.collector.{self.__class__.__name__}")
        self.running = False
        self._setup()
    
    @abc.abstractmethod
    def _setup(self) -> None:
        """Perform any necessary setup for the collector."""
        pass
    
    @abc.abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collect and return logs from the source.
        
        Returns:
            List of log entries as dictionaries
        """
        pass
    
    def normalize(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a log entry into the SIEM standard format.
        
        Args:
            log_entry: Raw log entry to normalize
            
        Returns:
            Normalized log entry
        """
        normalized = {
            "@timestamp": log_entry.get("@timestamp", datetime.utcnow().isoformat() + "Z"),
            "event": {
                "kind": "event",
                "category": log_entry.get("category", "unknown"),
                "type": log_entry.get("type", ["info"]),
                "severity": log_entry.get("severity", 0),
                "original": json.dumps(log_entry)
            },
            "log": {
                "level": log_entry.get("level", "info"),
                "logger": self.__class__.__name__
            },
            "message": log_entry.get("message", ""),
            "tags": ["siem", "collected"] + log_entry.get("tags", []),
            "labels": log_entry.get("labels", {})
        }
        
        # Add any additional fields from the original log
        for key, value in log_entry.items():
            if key not in normalized and not key.startswith("@"):
                normalized[key] = value
                
        return normalized
    
    def start(self) -> None:
        """Start the collector."""
        self.running = True
        self.logger.info(f"Started {self.__class__.__name__} collector")
    
    def stop(self) -> None:
        """Stop the collector."""
        self.running = False
        self.logger.info(f"Stopped {self.__class__.__name__} collector")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
