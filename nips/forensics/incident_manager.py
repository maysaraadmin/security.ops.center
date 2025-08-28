"""
Incident Manager for NIPS

Manages security incidents detected by the NIPS, including tracking, investigation,
and response coordination.
"""
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict, field
from enum import Enum, auto

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    """Severity levels for security incidents."""
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class IncidentStatus(Enum):
    """Possible statuses for a security incident."""
    OPEN = auto()
    UNDER_INVESTIGATION = auto()
    CONTAINED = auto()
    MITIGATED = auto()
    RESOLVED = auto()
    FALSE_POSITIVE = auto()

@dataclass
class Incident:
    """Represents a security incident detected by the NIPS."""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    detection_time: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    source_ips: Set[str] = field(default_factory=set)
    destination_ips: Set[str] = field(default_factory=set)
    related_events: List[Dict[str, Any]] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    assignee: Optional[str] = None
    notes: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the incident to a dictionary for serialization."""
        result = asdict(self)
        result['severity'] = self.severity.name
        result['status'] = self.status.name
        result['source_ips'] = list(self.source_ips)
        result['destination_ips'] = list(self.destination_ips)
        result['tags'] = list(self.tags)
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Incident':
        """Create an Incident from a dictionary."""
        # Convert string enums back to enum values
        data['severity'] = IncidentSeverity[data['severity']]
        data['status'] = IncidentStatus[data['status']]
        
        # Convert lists back to sets
        data['source_ips'] = set(data.get('source_ips', []))
        data['destination_ips'] = set(data.get('destination_ips', []))
        data['tags'] = set(data.get('tags', []))
        
        return cls(**data)

class IncidentManager:
    """Manages security incidents detected by the NIPS."""
    
    def __init__(self, storage_file: str = 'incidents.json'):
        """Initialize the Incident Manager.
        
        Args:
            storage_file: Path to the file where incidents will be stored
        """
        self.storage_file = storage_file
        self.incidents: Dict[str, Incident] = {}
        self._load_incidents()
    
    def _load_incidents(self):
        """Load incidents from the storage file."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    self.incidents = {
                        inc_id: Incident.from_dict(inc_data)
                        for inc_id, inc_data in data.items()
                    }
                logger.info(f"Loaded {len(self.incidents)} incidents from {self.storage_file}")
            except Exception as e:
                logger.error(f"Error loading incidents: {e}")
                self.incidents = {}
        else:
            logger.info("No existing incidents file found, starting with empty incident store")
    
    def _save_incidents(self):
        """Save incidents to the storage file."""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(
                    {inc_id: incident.to_dict() 
                     for inc_id, incident in self.incidents.items()},
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Error saving incidents: {e}")
    
    def create_incident(self, title: str, description: str, severity: IncidentSeverity,
                       source_ips: Optional[Set[str]] = None,
                       destination_ips: Optional[Set[str]] = None,
                       tags: Optional[Set[str]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create a new incident.
        
        Args:
            title: Short title for the incident
            description: Detailed description of the incident
            severity: Severity level
            source_ips: Set of source IP addresses involved
            destination_ips: Set of destination IP addresses involved
            tags: Set of tags for categorization
            metadata: Additional metadata about the incident
            
        Returns:
            str: The ID of the created incident
        """
        incident_id = f"inc_{int(time.time())}_{len(self.incidents) + 1}"
        
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            source_ips=source_ips or set(),
            destination_ips=destination_ips or set(),
            tags=tags or set(),
            metadata=metadata or {}
        )
        
        self.incidents[incident_id] = incident
        self._save_incidents()
        
        logger.info(f"Created new incident: {incident_id} - {title} ({severity.name})")
        return incident_id
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by ID.
        
        Args:
            incident_id: The ID of the incident to retrieve
            
        Returns:
            Optional[Incident]: The incident if found, None otherwise
        """
        return self.incidents.get(incident_id)
    
    def update_incident(self, incident_id: str, **updates) -> bool:
        """Update an existing incident.
        
        Args:
            incident_id: The ID of the incident to update
            **updates: Fields to update with their new values
            
        Returns:
            bool: True if the incident was updated, False if not found
        """
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        
        # Update fields if they exist in the Incident class
        for field, value in updates.items():
            if hasattr(incident, field):
                # Special handling for sets
                if field in ('source_ips', 'destination_ips', 'tags') and isinstance(value, (list, set)):
                    getattr(incident, field).update(value)
                else:
                    setattr(incident, field, value)
        
        # Always update the last_updated timestamp
        incident.last_updated = time.time()
        
        self._save_incidents()
        logger.info(f"Updated incident: {incident_id}")
        return True
    
    def add_note(self, incident_id: str, author: str, content: str) -> bool:
        """Add a note to an incident.
        
        Args:
            incident_id: The ID of the incident
            author: The author of the note
            content: The content of the note
            
        Returns:
            bool: True if the note was added, False if the incident was not found
        """
        if incident_id not in self.incidents:
            return False
        
        note = {
            'timestamp': time.time(),
            'author': author,
            'content': content
        }
        
        self.incidents[incident_id].notes.append(note)
        self.incidents[incident_id].last_updated = time.time()
        self._save_incidents()
        
        logger.info(f"Added note to incident {incident_id} by {author}")
        return True
    
    def list_incidents(self, status: Optional[IncidentStatus] = None,
                      severity: Optional[IncidentSeverity] = None,
                      tag: Optional[str] = None) -> List[Incident]:
        """List incidents matching the given filters.
        
        Args:
            status: Filter by status
            severity: Filter by severity
            tag: Filter by tag
            
        Returns:
            List[Incident]: List of matching incidents
        """
        result = []
        
        for incident in self.incidents.values():
            if status is not None and incident.status != status:
                continue
            if severity is not None and incident.severity != severity:
                continue
            if tag is not None and tag not in incident.tags:
                continue
                
            result.append(incident)
        
        # Sort by detection time (newest first)
        result.sort(key=lambda x: x.detection_time, reverse=True)
        return result
    
    def add_related_events(self, incident_id: str, events: List[Dict[str, Any]]) -> bool:
        """Add related events to an incident.
        
        Args:
            incident_id: The ID of the incident
            events: List of event dictionaries to add
            
        Returns:
            bool: True if events were added, False if the incident was not found
        """
        if incident_id not in self.incidents:
            return False
        
        self.incidents[incident_id].related_events.extend(events)
        self.incidents[incident_id].last_updated = time.time()
        self._save_incidents()
        
        logger.info(f"Added {len(events)} events to incident {incident_id}")
        return True
