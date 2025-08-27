"""
Base classes for event processing and correlation in SIEM.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
import json
import logging

class EventProcessor(ABC):
    """Abstract base class for event processors."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the processor with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(f"siem.processor.{self.__class__.__name__}")
    
    @abstractmethod
    def process(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single event.
        
        Args:
            event: The event to process
            
        Returns:
            Processed event or None if event should be dropped
        """
        pass
    
    def batch_process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of events.
        
        Args:
            events: List of events to process
            
        Returns:
            List of processed events (may be shorter than input)
        """
        return [e for e in (self.process(event) for event in events) if e is not None]


class CorrelationRule(ABC):
    """Base class for correlation rules."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the correlation rule."""
        self.config = config or {}
        self.logger = logging.getLogger(f"siem.rule.{self.__class__.__name__}")
        self.rule_id = self.config.get('id', self.__class__.__name__)
        self.severity = self.config.get('severity', 'medium')
        self.description = self.config.get('description', '')
        self.window = timedelta(seconds=self.config.get('window_seconds', 300))
        self.threshold = self.config.get('threshold', 1)
        self.alert_on = self.config.get('alert_on', 'match')
        
        # Storage for events being correlated
        self.events: List[Dict[str, Any]] = []
    
    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add an event to be correlated.
        
        Args:
            event: The event to add
            
        Returns:
            Correlation alert if conditions are met, otherwise None
        """
        # Clean up old events outside the time window
        self._cleanup_old_events()
        
        # Check if event matches the rule's conditions
        if not self._matches_condition(event):
            return None
            
        # Add event to the correlation window
        self.events.append(event)
        
        # Check if correlation conditions are met
        if self._check_conditions():
            return self._generate_alert()
        
        return None
    
    @abstractmethod
    def _matches_condition(self, event: Dict[str, Any]) -> bool:
        """Check if an event matches the rule's conditions.
        
        Args:
            event: The event to check
            
        Returns:
            True if the event matches, False otherwise
        """
        pass
    
    @abstractmethod
    def _check_conditions(self) -> bool:
        """Check if correlation conditions are met.
        
        Returns:
            True if conditions are met, False otherwise
        """
        pass
    
    def _cleanup_old_events(self) -> None:
        """Remove events that are outside the correlation window."""
        now = datetime.utcnow()
        self.events = [
            e for e in self.events 
            if now - datetime.fromisoformat(e['@timestamp'].replace('Z', '+00:00')) <= self.window
        ]
    
    def _generate_alert(self) -> Dict[str, Any]:
        """Generate a correlation alert.
        
        Returns:
            Alert event
        """
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': {
                'kind': 'alert',
                'category': 'correlation',
                'type': ['alert'],
                'severity': self.severity,
                'reason': self.description,
                'original': json.dumps([e['event'] for e in self.events])
            },
            'rule': {
                'id': self.rule_id,
                'description': self.description,
                'severity': self.severity,
                'window_seconds': self.window.total_seconds(),
                'threshold': self.threshold
            },
            'related': {
                'hosts': list({e.get('host', {}).get('name') for e in self.events if e.get('host', {}).get('name')}),
                'users': list({e.get('user', {}).get('name') for e in self.events if e.get('user', {}).get('name')}),
                'ips': list({
                    ip for e in self.events 
                    for ip in [e.get('source', {}).get('ip'), e.get('destination', {}).get('ip')] 
                    if ip
                })
            },
            'message': f"Correlation alert: {self.description}",
            'tags': ['siem', 'correlation', 'alert']
        }
