""
Event classes for EDR monitoring.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional
import time

@dataclass
class BaseEvent:
    """Base class for all monitoring events."""
    event_type: str
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization."""
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat()
        }

@dataclass
class ProcessEvent(BaseEvent):
    """Represents a process-related event."""
    pid: int
    ppid: int
    name: str
    path: str
    command_line: str
    username: str
    integrity_level: str = ''
    hashes: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data.update({
            'pid': self.pid,
            'ppid': self.ppid,
            'name': self.name,
            'path': self.path,
            'command_line': self.command_line,
            'username': self.username,
            'integrity_level': self.integrity_level,
            'hashes': self.hashes
        })
        return data

@dataclass
class FileEvent(BaseEvent):
    """Represents a file system event."""
    path: str
    is_directory: bool
    size: int = 0
    owner: str = ''
    hashes: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data.update({
            'path': self.path,
            'is_directory': self.is_directory,
            'size': self.size,
            'owner': self.owner,
            'hashes': self.hashes
        })
        return data

@dataclass
class RegistryEvent(BaseEvent):
    """Represents a Windows registry event."""
    key: str
    value_name: str = ''
    value_type: str = ''
    value_data: Any = None
    process_name: str = ''
    process_id: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data.update({
            'key': self.key,
            'value_name': self.value_name,
            'value_type': self.value_type,
            'value_data': str(self.value_data) if self.value_data is not None else None,
            'process_name': self.process_name,
            'process_id': self.process_id
        })
        return data

@dataclass
class NetworkEvent(BaseEvent):
    """Represents a network connection event."""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    pid: int
    process_name: str
    status: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data.update({
            'local_addr': self.local_addr,
            'local_port': self.local_port,
            'remote_addr': self.remote_addr,
            'remote_port': self.remote_port,
            'protocol': self.protocol,
            'pid': self.pid,
            'process_name': self.process_name,
            'status': self.status
        })
        return data

@dataclass
class UserActivityEvent(BaseEvent):
    """Represents user activity events."""
    username: str
    source_ip: str = ''
    session_id: str = ''
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = super().to_dict()
        data.update({
            'username': self.username,
            'source_ip': self.source_ip,
            'session_id': self.session_id,
            'details': self.details
        })
        return data
