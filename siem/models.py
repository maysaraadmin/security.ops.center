"""
Data models for the SIEM application.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from enum import Enum, auto
from typing import List, Dict, Any, Optional
import uuid


class EventSeverity(Enum):
    """Severity levels for events and alerts."""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AlertStatus(Enum):
    """Status of an alert."""
    NEW = "New"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    DISMISSED = "Dismissed"
    ESCALATED = "Escalated"
    SUPPRESSED = "Suppressed"


@dataclass
class Event:
    """Represents a security event."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    event_type: str = ""
    severity: EventSeverity = EventSeverity.INFO
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: str = ""
    tags: List[str] = field(default_factory=list)
    processed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'severity': self.severity.value,
            'description': self.description,
            'details': self.details,
            'raw_data': self.raw_data,
            'tags': self.tags,
            'processed': self.processed
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create an Event from a dictionary."""
        return cls(
            id=data.get('id', str(uuid.uuid4())),
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')) if 'timestamp' in data else datetime.now(UTC),
            source=data.get('source', ''),
            event_type=data.get('event_type', ''),
            severity=EventSeverity(data.get('severity', EventSeverity.INFO.value)),
            description=data.get('description', ''),
            details=data.get('details', {}),
            raw_data=data.get('raw_data', ''),
            tags=data.get('tags', []),
            processed=data.get('processed', False)
        )


@dataclass
class Alert:
    """Represents a security alert."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_ids: List[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    resolution_timestamp: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_ids': self.event_ids,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'assigned_to': self.assigned_to,
            'resolution': self.resolution,
            'resolution_timestamp': self.resolution_timestamp.isoformat() if self.resolution_timestamp else None,
            'details': self.details,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create an Alert from a dictionary."""
        resolution_timestamp = None
        if 'resolution_timestamp' in data and data['resolution_timestamp']:
            resolution_timestamp = datetime.fromisoformat(data['resolution_timestamp'].replace('Z', '+00:00'))
            
        return cls(
            id=data.get('id', str(uuid.uuid4())),
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')) if 'timestamp' in data else datetime.now(UTC),
            event_ids=data.get('event_ids', []),
            title=data.get('title', ''),
            description=data.get('description', ''),
            severity=EventSeverity(data.get('severity', EventSeverity.MEDIUM.value)),
            status=AlertStatus(data.get('status', AlertStatus.NEW.value)),
            assigned_to=data.get('assigned_to'),
            resolution=data.get('resolution'),
            resolution_timestamp=resolution_timestamp,
            details=data.get('details', {}),
            tags=data.get('tags', [])
        )


class EventManager:
    """Manages events and alerts in the SIEM system."""
    
    def __init__(self, max_events: int = 10000, max_alerts: int = 5000):
        self.events = []
        self.alerts = []
        self.max_events = max_events
        self.max_alerts = max_alerts
        self.event_callbacks = []
        self.alert_callbacks = []
    
    def add_event(self, event: Event) -> None:
        """Add a new event to the system."""
        self.events.append(event)
        
        # Remove oldest event if we've reached the maximum
        if len(self.events) > self.max_events:
            self.events.pop(0)
        
        # Notify subscribers
        self._notify_event_listeners(event)
    
    def add_alert(self, alert: Alert) -> None:
        """Add a new alert to the system."""
        self.alerts.append(alert)
        
        # Remove oldest alert if we've reached the maximum
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
        
        # Notify subscribers
        self._notify_alert_listeners(alert)
    
    def get_events(self, limit: int = 1000, **filters) -> List[Event]:
        """Get events matching the given filters."""
        events = self._filter_events(**filters)
        return events[-limit:]
    
    def get_alerts(self, limit: int = 500, **filters) -> List[Alert]:
        """Get alerts matching the given filters."""
        alerts = self._filter_alerts(**filters)
        return alerts[-limit:]
    
    def get_event(self, event_id: str) -> Optional[Event]:
        """Get an event by its ID."""
        for event in reversed(self.events):
            if event.id == event_id:
                return event
        return None
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by its ID."""
        for alert in reversed(self.alerts):
            if alert.id == alert_id:
                return alert
        return None
    
    def update_alert_status(self, alert_id: str, status: AlertStatus, 
                          resolution: str = None, assigned_to: str = None) -> bool:
        """Update the status of an alert."""
        alert = self.get_alert(alert_id)
        if not alert:
            return False
        
        alert.status = status
        if resolution:
            alert.resolution = resolution
        if assigned_to:
            alert.assigned_to = assigned_to
        
        if status in [AlertStatus.RESOLVED, AlertStatus.DISMISSED, AlertStatus.SUPPRESSED]:
            alert.resolution_timestamp = datetime.now(UTC)
        
        # Notify subscribers of the update
        self._notify_alert_listeners(alert, updated=True)
        return True
    
    def add_event_listener(self, callback) -> None:
        """Register a callback for new events."""
        if callback not in self.event_callbacks:
            self.event_callbacks.append(callback)
    
    def add_alert_listener(self, callback) -> None:
        """Register a callback for new alerts."""
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def _filter_events(self, **filters) -> List[Event]:
        """Filter events based on the given criteria."""
        if not filters:
            return self.events.copy()
        
        filtered = []
        for event in self.events:
            match = True
            for key, value in filters.items():
                if key == 'severity' and hasattr(event, key):
                    if isinstance(value, list):
                        if event.severity not in value:
                            match = False
                            break
                    elif event.severity != value:
                        match = False
                        break
                elif hasattr(event, key) and getattr(event, key) != value:
                    match = False
                    break
                elif key in event.details and event.details[key] != value:
                    match = False
                    break
            
            if match:
                filtered.append(event)
        
        return filtered
    
    def _filter_alerts(self, **filters) -> List[Alert]:
        """Filter alerts based on the given criteria."""
        if not filters:
            return self.alerts.copy()
        
        filtered = []
        for alert in self.alerts:
            match = True
            for key, value in filters.items():
                if key == 'status' and hasattr(alert, key):
                    if isinstance(value, list):
                        if alert.status not in value:
                            match = False
                            break
                    elif alert.status != value:
                        match = False
                        break
                elif hasattr(alert, key) and getattr(alert, key) != value:
                    match = False
                    break
                elif key in alert.details and alert.details[key] != value:
                    match = False
                    break
            
            if match:
                filtered.append(alert)
        
        return filtered
    
    def _notify_event_listeners(self, event: Event) -> None:
        """Notify all registered event listeners."""
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in event listener: {e}")
    
    def _notify_alert_listeners(self, alert: Alert, updated: bool = False) -> None:
        """Notify all registered alert listeners."""
        for callback in self.alert_callbacks:
            try:
                callback(alert, updated)
            except Exception as e:
                print(f"Error in alert listener: {e}")


# Example usage:
if __name__ == "__main__":
    # Create a test event
    test_event = Event(
        source="firewall",
        event_type="blocked_connection",
        severity=EventSeverity.MEDIUM,
        description="Blocked connection attempt",
        details={"ip": "192.168.1.100", "port": 445, "protocol": "TCP"}
    )
    
    # Create a test alert
    test_alert = Alert(
        title="Suspicious Connection Attempt",
        description="Multiple failed connection attempts detected",
        severity=EventSeverity.HIGH,
        event_ids=[test_event.id],
        details={"source_ip": "192.168.1.100", "target_port": 445, "attempts": 5}
    )
    
    print("Test event:", test_event.to_dict())
    print("Test alert:", test_alert.to_dict())
