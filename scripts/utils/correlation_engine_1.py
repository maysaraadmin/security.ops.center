"""
Event Correlation Engine for SIEM

This module provides real-time event correlation and analysis capabilities
to detect complex attack patterns and security incidents.
"""

import re
import time
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Callable, Pattern, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
import ipaddress
import hashlib
from collections import defaultdict, deque

# Configure logging
logger = logging.getLogger('siem.correlation_engine')

class Severity(Enum):
    """Standard severity levels for security events."""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class CorrelationRule:
    """Definition of a correlation rule for detecting security events."""
    id: str
    name: str
    description: str
    condition: str
    group_by: List[str] = field(default_factory=list)
    time_window: int = 300  # seconds
    threshold: int = 1
    severity: Severity = Severity.MEDIUM
    actions: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'condition': self.condition,
            'group_by': self.group_by,
            'time_window': self.time_window,
            'threshold': self.threshold,
            'severity': self.severity.name,
            'actions': self.actions,
            'tags': self.tags,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CorrelationRule':
        """Create a rule from a dictionary."""
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            condition=data['condition'],
            group_by=data.get('group_by', []),
            time_window=data.get('time_window', 300),
            threshold=data.get('threshold', 1),
            severity=Severity[data.get('severity', 'MEDIUM')],
            actions=data.get('actions', []),
            tags=data.get('tags', []),
            enabled=data.get('enabled', True),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow()
        )

@dataclass
class MatchedEvent:
    """Represents an event that matched a correlation rule."""
    rule_id: str
    event: Dict[str, Any]
    timestamp: datetime
    match_context: Dict[str, Any] = field(default_factory=dict)

class CorrelationEngine:
    """
    Real-time event correlation engine that processes incoming security events,
    applies correlation rules, and generates alerts when patterns are detected.
    """
    
    def __init__(self, rules: Optional[List[Dict]] = None):
        """
        Initialize the correlation engine with optional initial rules.
        
        Args:
            rules: Optional list of rule dictionaries to load
        """
        self.rules: Dict[str, CorrelationRule] = {}
        self.rule_conditions: Dict[str, Callable[[Dict], bool]] = {}
        self.rule_windows: Dict[str, Dict[Tuple, deque]] = {}
        self.rule_locks: Dict[str, threading.Lock] = {}
        self.callbacks: List[Callable[[Dict], None]] = []
        self.running = False
        self.cleanup_interval = 60  # seconds
        self.max_window_size = 10000  # Maximum events to keep in memory per rule/group
        
        # Load initial rules if provided
        if rules:
            self.load_rules(rules)
        
        # Start the cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_events, daemon=True)
    
    def start(self) -> None:
        """Start the correlation engine and cleanup thread."""
        if not self.running:
            self.running = True
            self.cleanup_thread.start()
            logger.info("Correlation engine started")
    
    def stop(self) -> None:
        """Stop the correlation engine and cleanup thread."""
        if self.running:
            self.running = False
            if self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=5)
            logger.info("Correlation engine stopped")
    
    def add_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Add a callback function to be called when a correlation is detected.
        
        Args:
            callback: Function that takes a correlation alert dictionary
        """
        if callable(callback) and callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def load_rules(self, rules: List[Dict]) -> None:
        """
        Load correlation rules from a list of dictionaries.
        
        Args:
            rules: List of rule dictionaries
        """
        for rule_data in rules:
            try:
                rule = CorrelationRule.from_dict(rule_data)
                self.add_rule(rule)
            except Exception as e:
                logger.error(f"Failed to load rule {rule_data.get('id', 'unknown')}: {e}")
    
    def add_rule(self, rule: CorrelationRule) -> bool:
        """
        Add a correlation rule to the engine.
        
        Args:
            rule: The correlation rule to add
            
        Returns:
            bool: True if the rule was added successfully, False otherwise
        """
        try:
            # Compile the condition into a callable function
            condition_func = self._compile_condition(rule.condition)
            
            # Store the rule and its compiled condition
            self.rules[rule.id] = rule
            self.rule_conditions[rule.id] = condition_func
            self.rule_windows[rule.id] = {}
            self.rule_locks[rule.id] = threading.Lock()
            
            logger.info(f"Added correlation rule: {rule.name} (ID: {rule.id})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add rule {rule.id}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a correlation rule from the engine.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            bool: True if the rule was removed, False otherwise
        """
        if rule_id in self.rules:
            with self.rule_locks[rule_id]:
                del self.rules[rule_id]
                del self.rule_conditions[rule_id]
                del self.rule_windows[rule_id]
                del self.rule_locks[rule_id]
            logger.info(f"Removed correlation rule: {rule_id}")
            return True
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict]:
        """
        Process a single security event through all correlation rules.
        
        Args:
            event: The event to process
            
        Returns:
            List of correlation alerts generated by the event
        """
        if not event or not isinstance(event, dict):
            return []
        
        alerts = []
        
        # Get the event timestamp (default to current time if not specified)
        event_time = event.get('@timestamp')
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                event_time = datetime.utcnow()
        elif not isinstance(event_time, datetime):
            event_time = datetime.utcnow()
        
        # Process the event against all rules
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
                
            try:
                # Check if the event matches the rule condition
                condition_func = self.rule_conditions[rule_id]
                if not condition_func(event):
                    continue
                
                # Get the group key for this rule and event
                group_key = self._get_group_key(rule, event)
                
                # Get the event window for this rule and group
                with self.rule_locks[rule_id]:
                    if group_key not in self.rule_windows[rule_id]:
                        self.rule_windows[rule_id][group_key] = deque(maxlen=self.max_window_size)
                    
                    # Add the event to the window
                    matched_event = MatchedEvent(
                        rule_id=rule_id,
                        event=event,
                        timestamp=event_time,
                        match_context={
                            'group_key': group_key,
                            'group_values': self._get_group_values(rule, event)
                        }
                    )
                    self.rule_windows[rule_id][group_key].append(matched_event)
                    
                    # Check if we've reached the threshold
                    if len(self.rule_windows[rule_id][group_key]) >= rule.threshold:
                        # Generate an alert
                        alert = self._generate_alert(rule, self.rule_windows[rule_id][group_key])
                        alerts.append(alert)
                        
                        # Notify callbacks
                        for callback in self.callbacks:
                            try:
                                callback(alert)
                            except Exception as e:
                                logger.error(f"Error in correlation callback: {e}")
                        
                        # Clear the window if configured to do so
                        if rule.actions and any(a.get('type') == 'reset_window' for a in rule.actions):
                            self.rule_windows[rule_id][group_key].clear()
            
            except Exception as e:
                logger.error(f"Error processing event with rule {rule_id}: {e}", exc_info=True)
        
        return alerts
    
    def _compile_condition(self, condition: str) -> Callable[[Dict], bool]:
        """
        Compile a condition string into a callable function.
        
        Args:
            condition: The condition string to compile
            
        Returns:
            A callable function that takes an event and returns a boolean
        """
        # Simple implementation - in a real system, you'd want a more robust parser
        # This is a simplified version that supports basic field comparisons
        
        # Check for common patterns
        if ' and ' in condition:
            parts = [p.strip() for p in condition.split(' and ')]
            conditions = [self._compile_condition(p) for p in parts]
            return lambda e: all(c(e) for c in conditions)
            
        if ' or ' in condition:
            parts = [p.strip() for p in condition.split(' or ')]
            conditions = [self._compile_condition(p) for p in parts]
            return lambda e: any(c(e) for c in conditions)
            
        if ' not in ' in condition:
            field, value = [p.strip() for p in condition.split(' not in ')]
            return lambda e: field in e and e[field] != value
            
        if ' in ' in condition:
            field, value = [p.strip() for p in condition.split(' in ')]
            return lambda e: field in e and e[field] == value
            
        if '>=' in condition:
            field, value = [p.strip() for p in condition.split('>=')]
            try:
                num_value = float(value)
                return lambda e: field in e and float(e[field]) >= num_value
            except (ValueError, TypeError):
                return lambda e: field in e and str(e[field]) >= value
                
        if '<=' in condition:
            field, value = [p.strip() for p in condition.split('<=')]
            try:
                num_value = float(value)
                return lambda e: field in e and float(e[field]) <= num_value
            except (ValueError, TypeError):
                return lambda e: field in e and str(e[field]) <= value
                
        if '>' in condition:
            field, value = [p.strip() for p in condition.split('>')]
            try:
                num_value = float(value)
                return lambda e: field in e and float(e[field]) > num_value
            except (ValueError, TypeError):
                return lambda e: field in e and str(e[field]) > value
                
        if '<' in condition:
            field, value = [p.strip() for p in condition.split('<')]
            try:
                num_value = float(value)
                return lambda e: field in e and float(e[field]) < num_value
            except (ValueError, TypeError):
                return lambda e: field in e and str(e[field]) < value
                
        if '!=' in condition:
            field, value = [p.strip() for p in condition.split('!=')]
            return lambda e: field in e and e[field] != value
            
        if '=' in condition:
            field, value = [p.strip() for p in condition.split('=', 1)]
            # Handle regex patterns
            if value.startswith('/') and value.endswith('/') and len(value) > 2:
                pattern = value[1:-1]
                try:
                    regex = re.compile(pattern)
                    return lambda e: field in e and bool(regex.search(str(e[field])))
                except re.error:
                    logger.warning(f"Invalid regex pattern: {pattern}")
                    return lambda e: False
            # Handle exact match
            return lambda e: field in e and e[field] == value
            
        # Default: check if the field exists and is truthy
        return lambda e: bool(e.get(condition.strip()))
    
    def _get_group_key(self, rule: CorrelationRule, event: Dict) -> Tuple:
        """
        Generate a group key for the given rule and event.
        
        Args:
            rule: The correlation rule
            event: The event to generate a group key for
            
        Returns:
            A tuple representing the group key
        """
        if not rule.group_by:
            return ('all',)
            
        key_parts = []
        for field in rule.group_by:
            value = event.get(field, '')
            # Convert to string and normalize
            key_parts.append(str(value).lower() if value is not None else '')
            
        return tuple(key_parts)
    
    def _get_group_values(self, rule: CorrelationRule, event: Dict) -> Dict[str, Any]:
        """
        Extract group values from an event.
        
        Args:
            rule: The correlation rule
            event: The event to extract values from
            
        Returns:
            Dictionary of group field names to values
        """
        if not rule.group_by:
            return {}
            
        return {field: event.get(field) for field in rule.group_by}
    
    def _generate_alert(self, rule: CorrelationRule, matched_events: List[MatchedEvent]) -> Dict:
        """
        Generate an alert from matched events.
        
        Args:
            rule: The correlation rule that was matched
            matched_events: List of matched events
            
        Returns:
            An alert dictionary
        """
        if not matched_events:
            return {}
            
        # Sort events by timestamp
        matched_events = sorted(matched_events, key=lambda e: e.timestamp)
        
        # Get the first and last events
        first_event = matched_events[0]
        last_event = matched_events[-1]
        
        # Count unique values for each field
        field_values = defaultdict(set)
        for event in matched_events:
            for k, v in event.event.items():
                field_values[k].add(str(v))
        
        # Get the most common values
        common_values = {
            k: self._get_most_common_value(vs)
            for k, vs in field_values.items()
        }
        
        # Create the alert
        alert = {
            'id': f"alert_{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:16]}",
            'rule_id': rule.id,
            'rule_name': rule.name,
            'description': rule.description,
            'severity': rule.severity.name.lower(),
            'status': 'open',
            'first_seen': first_event.timestamp.isoformat(),
            'last_seen': last_event.timestamp.isoformat(),
            'event_count': len(matched_events),
            'events': [e.event for e in matched_events],
            'group': first_event.match_context.get('group_values', {}),
            'common_values': common_values,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'tags': rule.tags.copy(),
            'actions': rule.actions.copy()
        }
        
        return alert
    
    def _get_most_common_value(self, values: Set) -> Any:
        """Get the most common value from a set, or the first if all are unique."""
        if not values:
            return None
            
        # If all values are the same, return any of them
        if len(values) == 1:
            return next(iter(values))
            
        # For multiple values, return a summary
        values_list = list(values)
        if len(values_list) <= 3:
            return ', '.join(str(v) for v in sorted(values_list))
        else:
            return f"{len(values_list)} unique values"
    
    def _cleanup_old_events(self) -> None:
        """Background thread to clean up old events from the windows."""
        while self.running:
            try:
                current_time = datetime.utcnow()
                
                for rule_id, rule in list(self.rules.items()):
                    if not rule.enabled or rule.time_window <= 0:
                        continue
                        
                    with self.rule_locks[rule_id]:
                        for group_key, window in list(self.rule_windows[rule_id].items()):
                            # Remove events older than the time window
                            while window and (current_time - window[0].timestamp).total_seconds() > rule.time_window:
                                window.popleft()
                            
                            # Remove empty groups
                            if not window:
                                del self.rule_windows[rule_id][group_key]
                
                # Sleep for the cleanup interval
                time.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}", exc_info=True)
                time.sleep(5)  # Prevent tight loop on error
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the correlation rules and their event windows.
        
        Returns:
            Dictionary containing statistics
        """
        stats = {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rules': []
        }
        
        for rule_id, rule in self.rules.items():
            rule_stats = {
                'id': rule.id,
                'name': rule.name,
                'enabled': rule.enabled,
                'window_count': len(self.rule_windows.get(rule_id, {})),
                'total_events': 0,
                'time_window': rule.time_window,
                'threshold': rule.threshold,
                'severity': rule.severity.name
            }
            
            # Count events in all windows for this rule
            for window in self.rule_windows.get(rule_id, {}).values():
                rule_stats['total_events'] += len(window)
            
            stats['rules'].append(rule_stats)
        
        return stats


# Example usage
if __name__ == "__main__":
    import random
    import string
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Sample correlation rules
    sample_rules = [
        {
            "id": "r1",
            "name": "Multiple Failed Logins",
            "description": "Detect multiple failed login attempts from the same IP",
            "condition": "message =~ /failed password/i and source_ip != ''",
            "group_by": ["source_ip", "user"],
            "time_window": 300,  # 5 minutes
            "threshold": 5,     # 5 failed attempts
            "severity": "HIGH",
            "actions": [
                {"type": "alert", "message": "Multiple failed login attempts from {{ source_ip }} for user {{ user }}"},
                {"type": "block_ip", "ip": "{{ source_ip }}", "duration": 3600}
            ],
            "tags": ["auth", "brute_force"]
        },
        {
            "id": "r2",
            "name": "Port Scan Detection",
            "description": "Detect port scanning activity",
            "condition": "event_type = 'connection_attempt' and destination_port > 0",
            "group_by": ["source_ip"],
            "time_window": 60,  # 1 minute
            "threshold": 20,    # 20 different ports
            "severity": "MEDIUM",
            "actions": [
                {"type": "alert", "message": "Possible port scan from {{ source_ip }}"}
            ],
            "tags": ["network", "scanning"]
        }
    ]
    
    # Create and start the correlation engine
    engine = CorrelationEngine(sample_rules)
    engine.start()
    
    # Add a callback to print alerts
    def alert_callback(alert):
        print(f"\n=== ALERT: {alert['rule_name']} ===")
        print(f"Severity: {alert['severity']}")
        print(f"Description: {alert['description']}")
        print(f"Event count: {alert['event_count']}")
        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")
        print(f"Group: {alert['group']}")
        print("Common values:")
        for k, v in alert['common_values'].items():
            print(f"  {k}: {v}")
        print()
    
    engine.add_callback(alert_callback)
    
    # Generate some test events
    print("Generating test events... (press Ctrl+C to stop)")
    
    try:
        users = ['alice', 'bob', 'charlie', 'dave', 'eve']
        ports = [22, 80, 443, 8080, 3306, 5432, 27017]
        
        while True:
            # Simulate failed logins
            if random.random() < 0.7:  # 70% chance of a failed login
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'message': f"Failed password for {random.choice(users)} from 192.168.1.{random.randint(1, 10)} port 22 ssh2",
                    'source_ip': f"192.168.1.{random.randint(1, 10)}",
                    'user': random.choice(users),
                    'event_type': 'authentication',
                    'status': 'failed',
                    'source': 'sshd'
                }
                engine.process_event(event)
            
            # Simulate connection attempts (port scans)
            if random.random() < 0.3:  # 30% chance of a connection attempt
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'connection_attempt',
                    'source_ip': f"10.0.0.{random.randint(1, 5)}",
                    'destination_ip': '192.168.1.100',
                    'destination_port': random.choice(ports),
                    'protocol': 'tcp',
                    'status': 'success' if random.random() > 0.5 else 'failed',
                    'source': 'firewall'
                }
                engine.process_event(event)
            
            # Print stats occasionally
            if random.random() < 0.05:  # 5% chance to print stats
                stats = engine.get_rule_stats()
                print(f"\nActive rules: {stats['enabled_rules']}/{stats['total_rules']}")
                for rule in stats['rules']:
                    print(f"- {rule['name']}: {rule['window_count']} active groups, {rule['total_events']} total events")
            
            time.sleep(0.1)  # Small delay between events
            
    except KeyboardInterrupt:
        print("\nStopping correlation engine...")
        engine.stop()
