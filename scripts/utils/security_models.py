"""Security-related data models and enums for the SIEM system."""
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List

class Severity(str, Enum):
    """Enumeration of security event severity levels."""
    INFO = 'INFO'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

class AlertStatus(str, Enum):
    """Enumeration of alert statuses."""
    OPEN = 'OPEN'
    IN_PROGRESS = 'IN_PROGRESS'
    RESOLVED = 'RESOLVED'
    FALSE_POSITIVE = 'FALSE_POSITIVE'
    IGNORED = 'IGNORED'

@dataclass
class EDREvent:
    """Data class representing an Endpoint Detection and Response (EDR) event."""
    event_type: str
    source: str
    description: str
    severity: Severity
    timestamp: datetime = None
    process_name: str = None
    process_id: int = None
    parent_process_id: int = None
    command_line: str = None
    file_path: str = None
    file_hash: str = None
    source_ip: str = None
    destination_ip: str = None
    user: str = None
    hostname: str = None
    raw_data: str = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        result = {
            'event_type': self.event_type,
            'source': self.source,
            'description': self.description,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
        }
        
        # Add optional fields if they exist
        optional_fields = [
            'process_name', 'process_id', 'parent_process_id', 'command_line',
            'file_path', 'file_hash', 'source_ip', 'destination_ip', 'user',
            'hostname', 'raw_data', 'metadata'
        ]
        
        for field in optional_fields:
            value = getattr(self, field, None)
            if value is not None:
                result[field] = value
                
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EDREvent':
        """Create an EDREvent from a dictionary."""
        return cls(**data)

@dataclass
class Alert:
    """Data class representing a security alert."""
    title: str
    description: str
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    timestamp: datetime = None
    source: str = 'SIEM'
    event_data: Dict[str, Any] = None
    assigned_to: str = None
    resolution: str = None
    
    def __post_init__(self):
        """Initialize timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.event_data is None:
            self.event_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert to a dictionary."""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_data': self.event_data,
            'assigned_to': self.assigned_to,
            'resolution': self.resolution
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create an Alert from a dictionary."""
        return cls(**data)
