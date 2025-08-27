from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
import json
from dataclasses import dataclass, asdict, field

class Severity(Enum):
    """Severity levels for security events and alerts."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(Enum):
    """Types of security events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    AUDIT = "audit"

class AlertStatus(Enum):
    """Status of security alerts."""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

@dataclass
class SecurityEvent:
    """Represents a security event in the SIEM system."""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = ""
    event_type: EventType = EventType.SYSTEM
    severity: Severity = Severity.INFO
    message: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    processed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat()
        data['raw_data'] = json.dumps(self.raw_data) if isinstance(self.raw_data, dict) else self.raw_data
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create an event from a dictionary."""
        if isinstance(data.get('raw_data'), str):
            try:
                data['raw_data'] = json.loads(data['raw_data'])
            except (json.JSONDecodeError, TypeError):
                data['raw_data'] = {}
        
        return cls(
            id=data.get('id'),
            timestamp=datetime.fromisoformat(data['timestamp']) if isinstance(data.get('timestamp'), str) else data.get('timestamp'),
            source=data.get('source', ''),
            event_type=EventType(data.get('event_type', 'system')),
            severity=Severity(data.get('severity', 'INFO')),
            message=data.get('message', ''),
            raw_data=data.get('raw_data', {}),
            processed=bool(data.get('processed', False))
        )

@dataclass
class Alert:
    """Represents a security alert in the SIEM system."""
    id: Optional[int] = None
    event_id: Optional[int] = None
    rule_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    status: AlertStatus = AlertStatus.NEW
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert to a dictionary."""
        data = asdict(self)
        data['status'] = self.status.value
        data['timestamp'] = self.timestamp.isoformat()
        data['details'] = json.dumps(self.details) if isinstance(self.details, dict) else self.details
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create an alert from a dictionary."""
        if isinstance(data.get('details'), str):
            try:
                data['details'] = json.loads(data['details'])
            except (json.JSONDecodeError, TypeError):
                data['details'] = {}
        
        return cls(
            id=data.get('id'),
            event_id=data.get('event_id'),
            rule_id=data.get('rule_id', ''),
            timestamp=datetime.fromisoformat(data['timestamp']) if isinstance(data.get('timestamp'), str) else data.get('timestamp'),
            status=AlertStatus(data.get('status', 'new')),
            description=data.get('description', ''),
            details=data.get('details', {})
        )

@dataclass
class ComplianceCheck:
    """Represents a compliance check result."""
    id: Optional[int] = None
    framework: str = ""
    control_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    status: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the compliance check to a dictionary."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['details'] = json.dumps(self.details) if isinstance(self.details, dict) else self.details
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComplianceCheck':
        """Create a compliance check from a dictionary."""
        if isinstance(data.get('details'), str):
            try:
                data['details'] = json.loads(data['details'])
            except (json.JSONDecodeError, TypeError):
                data['details'] = {}
        
        return cls(
            id=data.get('id'),
            framework=data.get('framework', ''),
            control_id=data.get('control_id', ''),
            timestamp=datetime.fromisoformat(data['timestamp']) if isinstance(data.get('timestamp'), str) else data.get('timestamp'),
            status=bool(data.get('status', False)),
            details=data.get('details', {})
        )

@dataclass
class CorrelationRule:
    """Represents a correlation rule for event correlation."""
    id: Optional[int] = None
    name: str = ""
    description: str = ""
    query: str = ""
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    actions: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['actions'] = json.dumps(self.actions) if isinstance(self.actions, (list, dict)) else self.actions
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CorrelationRule':
        """Create a rule from a dictionary."""
        if isinstance(data.get('actions'), str):
            try:
                data['actions'] = json.loads(data['actions'])
            except (json.JSONDecodeError, TypeError):
                data['actions'] = []
        
        return cls(
            id=data.get('id'),
            name=data.get('name', ''),
            description=data.get('description', ''),
            query=data.get('query', ''),
            severity=Severity(data.get('severity', 'MEDIUM')),
            enabled=bool(data.get('enabled', True)),
            actions=data.get('actions', [])
        )

@dataclass
class Incident:
    """Represents a security incident."""
    id: Optional[int] = None
    title: str = ""
    description: str = ""
    status: str = "open"
    severity: Severity = Severity.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    related_events: List[int] = field(default_factory=list)
    related_alerts: List[int] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident to a dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        data['resolved_at'] = self.resolved_at.isoformat() if self.resolved_at else None
        data['tags'] = json.dumps(self.tags) if isinstance(self.tags, list) else self.tags
        data['related_events'] = json.dumps(self.related_events) if isinstance(self.related_events, list) else self.related_events
        data['related_alerts'] = json.dumps(self.related_alerts) if isinstance(self.related_alerts, list) else self.related_alerts
        data['notes'] = json.dumps(self.notes) if isinstance(self.notes, list) else self.notes
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Incident':
        """Create an incident from a dictionary."""
        def parse_list(value, default=None):
            if value is None:
                return default or []
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return default or []
            return value
        
        resolved_at = data.get('resolved_at')
        if isinstance(resolved_at, str):
            resolved_at = datetime.fromisoformat(resolved_at)
        
        return cls(
            id=data.get('id'),
            title=data.get('title', ''),
            description=data.get('description', ''),
            status=data.get('status', 'open'),
            severity=Severity(data.get('severity', 'MEDIUM')),
            created_at=datetime.fromisoformat(data['created_at']) if isinstance(data.get('created_at'), str) else data.get('created_at'),
            updated_at=datetime.fromisoformat(data['updated_at']) if isinstance(data.get('updated_at'), str) else data.get('updated_at'),
            resolved_at=resolved_at,
            assigned_to=data.get('assigned_to'),
            tags=parse_list(data.get('tags'), []),
            related_events=parse_list(data.get('related_events'), []),
            related_alerts=parse_list(data.get('related_alerts'), []),
            notes=parse_list(data.get('notes'), [])
        )
