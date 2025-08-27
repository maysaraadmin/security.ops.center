"""
Timeline Analysis for EDR Incident Investigation.
Provides chronological analysis of security events and attack chains.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
import json
import logging
from enum import Enum
import hashlib

class EventType(str, Enum):
    """Types of events in the timeline."""
    PROCESS_CREATE = 'process_create'
    PROCESS_TERMINATE = 'process_terminate'
    FILE_CREATE = 'file_create'
    FILE_MODIFY = 'file_modify'
    FILE_DELETE = 'file_delete'
    NETWORK_CONNECTION = 'network_connection'
    REGISTRY_ACCESS = 'registry_access'
    USER_LOGIN = 'user_login'
    ALERT = 'alert'
    THREAT_DETECTED = 'threat_detected'
    MEMORY_ACCESS = 'memory_access'
    SCHEDULED_TASK = 'scheduled_task'
    SERVICE_CHANGE = 'service_change'
    PERSISTENCE = 'persistence'

@dataclass
class TimelineEvent:
    """Represents an event in the incident timeline."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    source: str
    description: str
    process: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    network: Optional[Dict[str, Any]] = None
    registry: Optional[Dict[str, Any]] = None
    user: Optional[Dict[str, Any]] = None
    endpoint: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'description': self.description,
            'process': self.process,
            'file': self.file,
            'network': self.network,
            'registry': self.registry,
            'user': self.user,
            'endpoint': self.endpoint,
            'metadata': self.metadata,
            'tags': self.tags,
            'raw_data': self.raw_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TimelineEvent':
        """Create event from dictionary."""
        return cls(
            event_id=data.get('event_id', ''),
            event_type=EventType(data['event_type']),
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')),
            source=data['source'],
            description=data['description'],
            process=data.get('process'),
            file=data.get('file'),
            network=data.get('network'),
            registry=data.get('registry'),
            user=data.get('user'),
            endpoint=data.get('endpoint'),
            metadata=data.get('metadata', {}),
            tags=data.get('tags', []),
            raw_data=data.get('raw_data')
        )

class TimelineAnalyzer:
    """Manages and analyzes timeline events for incident investigation."""
    
    def __init__(self, storage_backend: 'TimelineStorage'):
        """Initialize the timeline analyzer with a storage backend."""
        self.storage = storage_backend
        self.logger = logging.getLogger('edr.forensics.timeline')
    
    def add_event(self, event: TimelineEvent) -> bool:
        """Add an event to the timeline."""
        return self.storage.store_event(event)
    
    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
        source: Optional[str] = None,
        process_id: Optional[int] = None,
        file_path: Optional[str] = None,
        ip_address: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[TimelineEvent]:
        """
        Retrieve events matching the specified criteria.
        
        Args:
            start_time: Minimum timestamp for events
            end_time: Maximum timestamp for events
            event_types: List of event types to include
            source: Filter by event source
            process_id: Filter by process ID
            file_path: Filter by file path (partial match)
            ip_address: Filter by IP address
            tags: Filter by tags
            limit: Maximum number of events to return
            
        Returns:
            List of matching TimelineEvent objects
        """
        return self.storage.query_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_types,
            source=source,
            process_id=process_id,
            file_path=file_path,
            ip_address=ip_address,
            tags=tags,
            limit=limit
        )
    
    def get_event_chain(self, event_id: str, time_window: int = 3600) -> List[TimelineEvent]:
        """
        Get a chain of related events for a given event ID.
        
        Args:
            event_id: The ID of the event to build the chain around
            time_window: Time window in seconds to include before and after the event
            
        Returns:
            List of related TimelineEvent objects in chronological order
        """
        # Get the target event
        target_event = self.storage.get_event(event_id)
        if not target_event:
            return []
        
        # Get events in the time window around the target event
        start_time = target_event.timestamp - timedelta(seconds=time_window)
        end_time = target_event.timestamp + timedelta(seconds=time_window)
        
        # Get related events based on process, file, network, etc.
        related_events = []
        
        # Get events with the same process
        if target_event.process and target_event.process.get('pid'):
            related_events.extend(self.get_events(
                start_time=start_time,
                end_time=end_time,
                process_id=target_event.process['pid']
            ))
        
        # Get events with the same file
        if target_event.file and target_event.file.get('path'):
            related_events.extend(self.get_events(
                start_time=start_time,
                end_time=end_time,
                file_path=target_event.file['path']
            ))
        
        # Get events with the same network connection
        if target_event.network:
            if target_event.network.get('source_ip'):
                related_events.extend(self.get_events(
                    start_time=start_time,
                    end_time=end_time,
                    ip_address=target_event.network['source_ip']
                ))
            if target_event.network.get('dest_ip'):
                related_events.extend(self.get_events(
                    start_time=start_time,
                    end_time=end_time,
                    ip_address=target_event.network['dest_ip']
                ))
        
        # Remove duplicates and sort by timestamp
        unique_events = {e.event_id: e for e in related_events}
        if target_event.event_id not in unique_events:
            unique_events[target_event.event_id] = target_event
        
        return sorted(unique_events.values(), key=lambda x: x.timestamp)
    
    def generate_attack_chain(self, event_id: str) -> Dict[str, Any]:
        """
        Generate an attack chain visualization for a given event.
        
        Args:
            event_id: The ID of the event to analyze
            
        Returns:
            Dictionary containing the attack chain visualization
        """
        events = self.get_event_chain(event_id)
        if not events:
            return {
                'status': 'error',
                'message': 'No events found for the specified ID',
                'attack_chain': []
            }
        
        # Group events by process
        process_chains = {}
        for event in events:
            if event.process and event.process.get('pid'):
                pid = event.process['pid']
                if pid not in process_chains:
                    process_chains[pid] = {
                        'process': event.process,
                        'events': []
                    }
                process_chains[pid]['events'].append(event)
        
        # Build attack chain
        attack_chain = []
        for pid, chain in process_chains.items():
            # Sort events by timestamp
            chain['events'].sort(key=lambda x: x.timestamp)
            
            # Add process start event
            process_start = {
                'type': 'process',
                'event_type': 'process_start',
                'timestamp': chain['events'][0].timestamp.isoformat(),
                'process': chain['process'],
                'events': []
            }
            
            # Add child events
            for event in chain['events']:
                process_start['events'].append({
                    'event_id': event.event_id,
                    'event_type': event.event_type,
                    'timestamp': event.timestamp.isoformat(),
                    'description': event.description,
                    'source': event.source,
                    'tags': event.tags
                })
            
            attack_chain.append(process_start)
        
        # Sort attack chain by timestamp of first event in each process
        attack_chain.sort(key=lambda x: x['timestamp'])
        
        return {
            'status': 'success',
            'event_count': len(events),
            'process_count': len(process_chains),
            'attack_chain': attack_chain
        }

class TimelineStorage:
    """Abstract base class for timeline storage backends."""
    
    def store_event(self, event: TimelineEvent) -> bool:
        """Store a timeline event."""
        raise NotImplementedError
    
    def get_event(self, event_id: str) -> Optional[TimelineEvent]:
        """Retrieve a timeline event by ID."""
        raise NotImplementedError
    
    def query_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
        source: Optional[str] = None,
        process_id: Optional[int] = None,
        file_path: Optional[str] = None,
        ip_address: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[TimelineEvent]:
        """Query timeline events based on criteria."""
        raise NotImplementedError
