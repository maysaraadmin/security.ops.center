"""
SIEM Log Collection Module

This module provides a flexible framework for collecting logs from various sources.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import logging
import json
from datetime import datetime

class LogSource(ABC):
    """Abstract base class for log sources"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.is_running = False
        self.logger = logging.getLogger(f"siem.collector.{name}")
    
    @abstractmethod
    def start(self) -> None:
        """Start collecting logs from this source"""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop collecting logs from this source"""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of this log source"""
        pass

class FileLogSource(LogSource):
    """Collect logs from files"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.file_path = config.get('path')
        self.last_position = 0
        self.batch_size = config.get('batch_size', 100)
    
    def start(self) -> None:
        self.logger.info(f"Starting file log collection from {self.file_path}")
        self.is_running = True
        # In a real implementation, this would start a background thread
        
    def stop(self) -> None:
        self.logger.info(f"Stopping file log collection from {self.file_path}")
        self.is_running = False
    
    def get_status(self) -> Dict[str, Any]:
        return {
            'type': 'file',
            'path': self.file_path,
            'last_position': self.last_position,
            'is_running': self.is_running
        }
    
    def read_new_entries(self) -> List[Dict[str, Any]]:
        """Read new log entries since last read"""
        entries = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                # Move to last read position
                f.seek(self.last_position)
                
                # Read new lines
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry['@timestamp'] = datetime.utcnow().isoformat()
                        entry['log_source'] = self.name
                        entries.append(entry)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Invalid JSON in log file: {line}")
                
                # Update position
                self.last_position = f.tell()
                
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.file_path}")
        
        return entries

class SyslogSource(LogSource):
    """Collect logs via Syslog protocol"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp')
        self.server = None
    
    def start(self) -> None:
        self.logger.info(f"Starting syslog server on {self.host}:{self.port}/{self.protocol}")
        # In a real implementation, this would start a syslog server
        self.is_running = True
    
    def stop(self) -> None:
        self.logger.info("Stopping syslog server")
        # In a real implementation, this would stop the syslog server
        self.is_running = False
    
    def get_status(self) -> Dict[str, Any]:
        return {
            'type': 'syslog',
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'is_running': self.is_running
        }

class LogCollector:
    """Manages multiple log sources"""
    
    def __init__(self):
        self.sources: Dict[str, LogSource] = {}
        self.logger = logging.getLogger('siem.collector')
    
    def add_source(self, name: str, source_type: str, config: Dict[str, Any]) -> bool:
        """Add a new log source"""
        if name in self.sources:
            self.logger.warning(f"Log source '{name}' already exists")
            return False
            
        source = None
        if source_type == 'file':
            source = FileLogSource(name, config)
        elif source_type == 'syslog':
            source = SyslogSource(name, config)
        else:
            self.logger.error(f"Unknown log source type: {source_type}")
            return False
        
        self.sources[name] = source
        return True
    
    def start_all(self) -> None:
        """Start all log sources"""
        for name, source in self.sources.items():
            try:
                source.start()
                self.logger.info(f"Started log source: {name}")
            except Exception as e:
                self.logger.error(f"Failed to start log source {name}: {str(e)}")
    
    def stop_all(self) -> None:
        """Stop all log sources"""
        for name, source in self.sources.items():
            try:
                source.stop()
                self.logger.info(f"Stopped log source: {name}")
            except Exception as e:
                self.logger.error(f"Error stopping log source {name}: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all log sources"""
        return {
            'sources': {
                name: source.get_status() 
                for name, source in self.sources.items()
            }
        }
    
    def collect_logs(self) -> List[Dict[str, Any]]:
        """Collect logs from all sources"""
        all_logs = []
        for source in self.sources.values():
            if isinstance(source, FileLogSource):
                logs = source.read_new_entries()
                all_logs.extend(logs)
        return all_logs
