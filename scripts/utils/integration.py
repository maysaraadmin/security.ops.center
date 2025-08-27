"""
Security Operations Center - Core Integration Module

This module provides the core integration between different security components
in the Security Operations Center (SOC).
"""

import logging
import time
import json
import threading
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import queue
import uuid
import hashlib
from datetime import datetime, timedelta

logger = logging.getLogger('soc.integration')

class ComponentType(Enum):
    """Enumeration of security component types."""
    SIEM = "siem"
    EDR = "edr"
    NDR = "ndr"
    NIPS = "nips"
    DLP = "dlp"
    FIM = "fim"
    HIPS = "hips"
    THREAT_INTEL = "threat_intel"
    RESPONSE_ENGINE = "response_engine"

class EventSeverity(Enum):
    """Standard severity levels for security events."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class SecurityEvent:
    """Standardized security event format for cross-component communication."""
    event_id: str
    component: ComponentType
    event_type: str
    timestamp: float
    severity: EventSeverity
    details: Dict[str, Any]
    source: Dict[str, str]
    related_events: List[str] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    raw_event: Optional[Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        return {
            'event_id': self.event_id,
            'component': self.component.value,
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'severity': self.severity.name,
            'details': self.details,
            'source': self.source,
            'related_events': self.related_events,
            'iocs': self.iocs,
            'raw_event': str(self.raw_event) if self.raw_event else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create a SecurityEvent from a dictionary."""
        return cls(
            event_id=data.get('event_id', str(uuid.uuid4())),
            component=ComponentType(data['component']),
            event_type=data['event_type'],
            timestamp=data.get('timestamp', time.time()),
            severity=EventSeverity[data.get('severity', 'INFO')],
            details=data.get('details', {}),
            source=data.get('source', {}),
            related_events=data.get('related_events', []),
            iocs=data.get('iocs', []),
            raw_event=data.get('raw_event')
        )

class IOCType(Enum):
    """Types of Indicators of Compromise (IoCs)."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    CMDLINE = "command_line"
    USER_AGENT = "user_agent"
    JA3 = "ja3"
    CERTIFICATE = "certificate"

@dataclass
class IndicatorOfCompromise:
    """Standardized Indicator of Compromise (IoC) format."""
    type: IOCType
    value: str
    first_seen: float
    last_seen: float
    source: str
    confidence: float  # 0.0 to 1.0
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the IoC to a dictionary."""
        return {
            'type': self.type.value,
            'value': self.value,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'source': self.source,
            'confidence': self.confidence,
            'tags': self.tags,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IndicatorOfCompromise':
        """Create an IoC from a dictionary."""
        return cls(
            type=IOCType(data['type']),
            value=data['value'],
            first_seen=data.get('first_seen', time.time()),
            last_seen=data.get('last_seen', time.time()),
            source=data['source'],
            confidence=data.get('confidence', 0.5),
            tags=data.get('tags', []),
            description=data.get('description')
        )

class SOCIntegrationHub:
    """Central hub for integrating security components."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the SOC Integration Hub."""
        self.config = config or {}
        self.components: Dict[str, Dict[str, Any]] = {}
        self.event_handlers: Dict[str, List[Callable[[SecurityEvent], None]]] = {}
        self.ioc_store: Dict[Tuple[IOCType, str], IndicatorOfCompromise] = {}
        self.ioc_lock = threading.Lock()
        self.event_queue = queue.Queue(maxsize=10000)
        self.running = False
        self.worker_thread = threading.Thread(target=self._process_events, daemon=True)
        
        # Start the event processing thread
        self.running = True
        self.worker_thread.start()
        
        logger.info("SOC Integration Hub initialized")
    
    def register_component(self, component_id: str, component_type: ComponentType, 
                         callback: Optional[Callable[[SecurityEvent], None]] = None) -> bool:
        """Register a security component with the hub."""
        if component_id in self.components:
            logger.warning(f"Component with ID {component_id} is already registered")
            return False
            
        self.components[component_id] = {
            'type': component_type,
            'last_seen': time.time(),
            'status': 'online',
            'callback': callback
        }
        
        logger.info(f"Registered component: {component_id} ({component_type.value})")
        return True
    
    def unregister_component(self, component_id: str) -> bool:
        """Unregister a security component."""
        if component_id not in self.components:
            return False
            
        del self.components[component_id]
        logger.info(f"Unregistered component: {component_id}")
        return True
    
    def publish_event(self, event: SecurityEvent) -> bool:
        """Publish a security event to the hub."""
        try:
            # Add to processing queue
            self.event_queue.put(event, block=False)
            return True
        except queue.Full:
            logger.error("Event queue is full, dropping event")
            return False
    
    def _process_events(self) -> None:
        """Background thread for processing events."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                if event is None:
                    continue
                
                # Update IoC store
                self._update_iocs(event)
                
                # Route to interested components
                self._route_event(event)
                
                # Call registered event handlers
                self._call_event_handlers(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
    
    def _update_iocs(self, event: SecurityEvent) -> None:
        """Update IoC store with indicators from the event."""
        with self.ioc_lock:
            for ioc_data in event.iocs:
                try:
                    ioc = IndicatorOfCompromise.from_dict(ioc_data)
                    key = (ioc.type, ioc.value)
                    
                    if key in self.ioc_store:
                        # Update existing IoC
                        existing = self.ioc_store[key]
                        existing.last_seen = max(existing.last_seen, ioc.last_seen)
                        existing.confidence = max(existing.confidence, ioc.confidence)
                        existing.tags = list(set(existing.tags + ioc.tags))
                    else:
                        # Add new IoC
                        self.ioc_store[key] = ioc
                        
                except Exception as e:
                    logger.error(f"Error updating IoC: {e}", exc_info=True)
    
    def _route_event(self, event: SecurityEvent) -> None:
        """Route event to interested components."""
        for component_id, component in self.components.items():
            try:
                # Skip if no callback is registered
                if not component['callback']:
                    continue
                
                # Simple routing logic - in a real implementation, this would be more sophisticated
                if self._should_route_event(event, component):
                    component['callback'](event)
                    
            except Exception as e:
                logger.error(f"Error routing event to {component_id}: {e}", exc_info=True)
    
    def _should_route_event(self, event: SecurityEvent, component: Dict[str, Any]) -> bool:
        """Determine if an event should be routed to a component."""
        # Default routing rules
        component_type = component['type']
        
        # SIEM gets all events
        if component_type == ComponentType.SIEM:
            return True
            
        # EDR cares about endpoint events
        if component_type == ComponentType.EDR and event.component in [
            ComponentType.EDR, ComponentType.HIPS, ComponentType.FIM
        ]:
            return True
            
        # NDR/NIPS care about network events
        if component_type in [ComponentType.NDR, ComponentType.NIPS] and event.component in [
            ComponentType.NDR, ComponentType.NIPS
        ]:
            return True
            
        # Response engine cares about high-severity events
        if component_type == ComponentType.RESPONSE_ENGINE and event.severity in [
            EventSeverity.HIGH, EventSeverity.CRITICAL
        ]:
            return True
            
        return False
    
    def register_event_handler(self, event_type: str, handler: Callable[[SecurityEvent], None]) -> None:
        """Register a handler for specific event types."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def _call_event_handlers(self, event: SecurityEvent) -> None:
        """Call all registered event handlers for the event type."""
        for handler in self.event_handlers.get('*', []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler: {e}", exc_info=True)
                
        for handler in self.event_handlers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler for {event.event_type}: {e}", exc_info=True)
    
    def get_iocs(self, ioc_type: Optional[IOCType] = None) -> List[IndicatorOfCompromise]:
        """Get all IoCs of a specific type, or all IoCs if no type is specified."""
        with self.ioc_lock:
            if ioc_type is None:
                return list(self.ioc_store.values())
            return [ioc for (t, _), ioc in self.ioc_store.items() if t == ioc_type]
    
    def search_iocs(self, query: str, ioc_type: Optional[IOCType] = None) -> List[IndicatorOfCompromise]:
        """Search for IoCs matching a query."""
        results = []
        with self.ioc_lock:
            for (t, v), ioc in self.ioc_store.items():
                if (ioc_type is None or t == ioc_type) and query.lower() in v.lower():
                    results.append(ioc)
        return results
    
    def get_related_events(self, event_id: str) -> List[SecurityEvent]:
        """Get all events related to a specific event."""
        # In a real implementation, this would query the event database
        return []
    
    def get_component_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered components."""
        status = {}
        for component_id, component in self.components.items():
            status[component_id] = {
                'type': component['type'].value,
                'status': component['status'],
                'last_seen': component['last_seen']
            }
        return status
    
    def stop(self) -> None:
        """Stop the integration hub and clean up resources."""
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
        logger.info("SOC Integration Hub stopped")

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create the integration hub
    hub = SOCIntegrationHub()
    
    # Example component registration
    def siem_event_handler(event: SecurityEvent):
        print(f"SIEM received event: {event.event_type}")
    
    hub.register_component("siem-01", ComponentType.SIEM, siem_event_handler)
    
    # Example event publishing
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        component=ComponentType.EDR,
        event_type="malware_detected",
        timestamp=time.time(),
        severity=EventSeverity.HIGH,
        details={
            "threat_name": "Example.Malware",
            "file_path": "C:\\Windows\\System32\\malware.exe",
            "process_id": 1234,
            "user": "DOMAIN\\user"
        },
        source={
            "component_id": "edr-01",
            "hostname": "workstation-01",
            "ip_address": "192.168.1.100"
        },
        iocs=[
            {
                "type": "hash",
                "value": "a1b2c3d4e5f6...",
                "first_seen": time.time() - 3600,
                "last_seen": time.time(),
                "source": "edr-01",
                "confidence": 0.9,
                "tags": ["malware", "trojan"],
                "description": "Known malicious file hash"
            }
        ]
    )
    
    # Publish the event
    hub.publish_event(event)
    
    # Keep the script running to process events
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hub.stop()
