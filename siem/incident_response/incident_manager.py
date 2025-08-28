"""
Incident Management System for SIEM.

This module handles the creation, tracking, and management of security incidents.
"""
import uuid
import json
import logging
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
import hashlib

logger = logging.getLogger(__name__)

class IncidentStatus(Enum):
    """Represents the status of an incident."""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positiv"

class IncidentSeverity(Enum):
    """Represents the severity of an incident."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentClassification(Enum):
    """Standard classification of security incidents."""
    MALWARE = "malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    DOS = "denial_of_service"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OTHER = "other"

@dataclass
class Evidence:
    """Represents a piece of evidence in an incident."""
    id: str
    type: str  # log, file, memory, network, etc.
    source: str
    collected_at: datetime
    collected_by: str
    description: str
    hash: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TimelineEvent:
    """An event in the incident timeline."""
    timestamp: datetime
    event_type: str
    description: str
    actor: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Incident:
    """Represents a security incident."""
    id: str
    title: str
    description: str
    status: IncidentStatus
    severity: IncidentSeverity
    classification: IncidentClassification
    created_at: datetime
    created_by: str
    updated_at: datetime
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None
    assignee: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to the incident."""
        self.evidence.append(evidence)
        self._update_timeline(
            "evidence_added",
            f"Added evidence: {evidence.description}",
            "system",
            {"evidence_id": evidence.id, "type": evidence.type}
        )
    
    def update_status(self, new_status: IncidentStatus, updated_by: str, comment: str = "") -> None:
        """Update the status of the incident."""
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.utcnow()
        
        if new_status in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.REMEDIATED]:
            self.closed_at = self.updated_at
            self.closed_by = updated_by
        
        self._update_timeline(
            "status_changed",
            f"Status changed from {old_status.value} to {new_status.value}" + (f": {comment}" if comment else ""),
            updated_by,
            {"old_status": old_status.value, "new_status": new_status.value}
        )
    
    def add_comment(self, comment: str, author: str) -> None:
        """Add a comment to the incident."""
        self._update_timeline("comment_added", f"Comment: {comment}", author)
    
    def add_related_alert(self, alert_id: str) -> None:
        """Add a related alert to the incident."""
        if alert_id not in self.related_alerts:
            self.related_alerts.append(alert_id)
            self._update_timeline("alert_linked", f"Linked alert: {alert_id}", "system")
    
    def _update_timeline(self, event_type: str, description: str, actor: str, details: Optional[Dict] = None) -> None:
        """Add an event to the incident timeline."""
        self.timeline.append(TimelineEvent(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            description=description,
            actor=actor,
            details=details or {}
        ))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident to a dictionary."""
        result = asdict(self)
        # Convert enums to their values
        result['status'] = self.status.value
        result['severity'] = self.severity.value
        result['classification'] = self.classification.value
        # Convert datetime objects to ISO format
        for time_field in ['created_at', 'updated_at', 'closed_at']:
            if result[time_field]:
                result[time_field] = result[time_field].isoformat()
        # Convert timeline events
        result['timeline'] = [{
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'description': event.description,
            'actor': event.actor,
            'details': event.details
        } for event in self.timeline]
        return result

class IncidentManager:
    """Manages security incidents and their lifecycle."""
    
    def __init__(self, storage_backend: Any = None):
        """Initialize the incident manager.
        
        Args:
            storage_backend: Backend for persisting incidents (optional)
        """
        self.storage = storage_backend
        self.incidents: Dict[str, Incident] = {}
        self.incident_counter = 0
        self._load_incidents()
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        classification: IncidentClassification,
        created_by: str,
        related_alerts: Optional[List[str]] = None,
        tags: Optional[Set[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Create a new incident."""
        incident_id = self._generate_incident_id()
        now = datetime.utcnow()
        
        incident = Incident(
            id=incident_id,
            title=title,
            description=description,
            status=IncidentStatus.NEW,
            severity=severity,
            classification=classification,
            created_at=now,
            created_by=created_by,
            updated_at=now,
            tags=tags or set(),
            related_alerts=related_alerts or [],
            custom_fields=custom_fields or {}
        )
        
        self.incidents[incident_id] = incident
        self._save_incident(incident)
        
        # Add initial timeline event
        incident._update_timeline(
            "incident_created",
            f"Incident created by {created_by}",
            created_by
        )
        
        logger.info(f"Created new incident {incident_id}: {title}")
        return incident
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by ID."""
        return self.incidents.get(incident_id)
    
    def update_incident_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        updated_by: str,
        comment: str = ""
    ) -> bool:
        """Update the status of an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return False
        
        incident.update_status(new_status, updated_by, comment)
        self._save_incident(incident)
        return True
    
    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        source: str,
        description: str,
        collected_by: str,
        **kwargs
    ) -> Optional[Evidence]:
        """Add evidence to an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        
        evidence = Evidence(
            id=str(uuid.uuid4()),
            type=evidence_type,
            source=source,
            description=description,
            collected_at=datetime.utcnow(),
            collected_by=collected_by,
            **{k: v for k, v in kwargs.items() if k in Evidence.__annotations__}
        )
        
        incident.add_evidence(evidence)
        self._save_incident(incident)
        return evidence
    
    def search_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        classification: Optional[IncidentClassification] = None,
        tag: Optional[str] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        assignee: Optional[str] = None
    ) -> List[Incident]:
        """Search for incidents matching the given criteria."""
        results = []
        
        for incident in self.incidents.values():
            if status and incident.status != status:
                continue
            if severity and incident.severity != severity:
                continue
            if classification and incident.classification != classification:
                continue
            if tag and tag not in incident.tags:
                continue
            if time_range and not (time_range[0] <= incident.created_at <= time_range[1]):
                continue
            if assignee and incident.assignee != assignee:
                continue
                
            results.append(incident)
        
        return results
    
    def _generate_incident_id(self) -> str:
        """Generate a unique incident ID."""
        self.incident_counter += 1
        return f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{self.incident_counter:04d}"
    
    def _save_incident(self, incident: Incident) -> None:
        """Save an incident to the storage backend."""
        if self.storage:
            self.storage.save_incident(incident)
    
    def _load_incidents(self) -> None:
        """Load incidents from the storage backend."""
        if self.storage:
            self.incidents = {inc.id: inc for inc in self.storage.load_incidents()}
            self.incident_counter = len(self.incidents)

def create_incident_from_alert(alert: Dict[str, Any], created_by: str = "system") -> Incident:
    """Create an incident from an alert."""
    # Map alert severity to incident severity
    severity_map = {
        'info': IncidentSeverity.INFO,
        'low': IncidentSeverity.LOW,
        'medium': IncidentSeverity.MEDIUM,
        'high': IncidentSeverity.HIGH,
        'critical': IncidentSeverity.CRITICAL
    }
    
    # Default classification if not specified
    classification = IncidentClassification.OTHER
    if 'classification' in alert:
        try:
            classification = IncidentClassification(alert['classification'])
        except ValueError:
            pass
    
    # Create the incident
    incident = Incident(
        id=f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{hashlib.md5(str(alert.get('id', '')).encode()).hexdigest()[:6]}",
        title=alert.get('title', 'Security Incident'),
        description=alert.get('description', 'No description provided'),
        status=IncidentStatus.NEW,
        severity=severity_map.get(alert.get('severity', 'medium').lower(), IncidentSeverity.MEDIUM),
        classification=classification,
        created_at=datetime.utcnow(),
        created_by=created_by,
        updated_at=datetime.utcnow(),
        tags=set(alert.get('tags', [])),
        related_alerts=[alert.get('id')] if 'id' in alert else []
    )
    
    return incident
