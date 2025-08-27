"""
Security Information and Event Management (SIEM) Engine

This module provides the core SIEM functionality including event collection,
correlation, alerting, and reporting.
"""

import logging
import time
import json
import threading
import queue
import uuid
import re
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Pattern
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum, auto
import hashlib

# Import from our SOC integration module
from soc.core.integration import (
    SOCIntegrationHub, SecurityEvent, EventSeverity, ComponentType, IndicatorOfCompromise, IOCType
)

logger = logging.getLogger('siem.engine')

class CorrelationRule:
    """Defines a correlation rule for detecting security incidents."""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                conditions: List[Dict[str, Any]], 
                actions: List[Dict[str, Any]],
                severity: EventSeverity = EventSeverity.MEDIUM,
                time_window: int = 300,
                enabled: bool = True):
        """Initialize a correlation rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            description: Detailed description
            conditions: List of conditions that must be met
            actions: Actions to take when the rule triggers
            severity: Severity of the resulting alert
            time_window: Time window in seconds for event correlation
            enabled: Whether the rule is enabled
        """
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.conditions = conditions
        self.actions = actions
        self.severity = severity
        self.time_window = time_window
        self.enabled = enabled
        self.last_triggered: Optional[float] = None
        self.trigger_count: int = 0
        
        # Compile regex patterns for performance
        self._compiled_patterns: Dict[str, Pattern] = {}
        for condition in self.conditions:
            if 'pattern' in condition and isinstance(condition['pattern'], str):
                try:
                    self._compiled_patterns[condition['field']] = re.compile(condition['pattern'])
                except re.error as e:
                    logger.error(f"Invalid regex pattern in rule {rule_id}: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'actions': self.actions,
            'severity': self.severity.name,
            'time_window': self.time_window,
            'enabled': self.enabled,
            'last_triggered': self.last_triggered,
            'trigger_count': self.trigger_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CorrelationRule':
        """Create a CorrelationRule from a dictionary."""
        rule = cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data.get('description', ''),
            conditions=data['conditions'],
            actions=data['actions'],
            severity=EventSeverity[data.get('severity', 'MEDIUM')],
            time_window=data.get('time_window', 300),
            enabled=data.get('enabled', True)
        )
        
        if 'last_triggered' in data:
            rule.last_triggered = data['last_triggered']
        if 'trigger_count' in data:
            rule.trigger_count = data['trigger_count']
            
        return rule

class SIEMEngine:
    """Core SIEM engine for event processing and correlation."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the SIEM engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rules: Dict[str, CorrelationRule] = {}
        self.rule_lock = threading.Lock()
        self.event_store: Dict[str, SecurityEvent] = {}
        self.event_store_lock = threading.Lock()
        self.event_index: Dict[Tuple[str, str], Set[str]] = {}
        self.running = False
        self.soc_hub: Optional[SOCIntegrationHub] = None
        
        # Event processing queue
        self.event_queue = queue.Queue(maxsize=10000)
        self.worker_thread = threading.Thread(target=self._process_events, daemon=True)
        
        # Alert handlers
        self.alert_handlers: List[Callable[[Dict[str, Any]], None]] = []
        
        # Load default rules if none are provided
        if not self.rules:
            self._load_default_rules()
        
        # Start the event processing thread
        self.running = True
        self.worker_thread.start()
        
        logger.info("SIEM Engine initialized")
    
    def connect_to_hub(self, hub: SOCIntegrationHub) -> None:
        """Connect to the SOC integration hub."""
        self.soc_hub = hub
        hub.register_component("siem-engine", ComponentType.SIEM, self._handle_security_event)
        logger.info("Connected to SOC Integration Hub")
    
    def _load_default_rules(self) -> None:
        """Load default correlation rules."""
        default_rules = [
            {
                'rule_id': 'multiple_failed_logins',
                'name': 'Multiple Failed Login Attempts',
                'description': 'Detect multiple failed login attempts from the same source',
                'severity': 'HIGH',
                'time_window': 300,  # 5 minutes
                'conditions': [
                    {'field': 'event_type', 'op': '==', 'value': 'authentication_failure'},
                    {'field': 'count', 'op': '>=', 'value': 5, 'group_by': ['source.ip_address', 'details.username']}
                ],
                'actions': [
                    {'action': 'create_alert', 'severity': 'HIGH', 
                     'message': 'Multiple failed login attempts for user {details.username} from {source.ip_address}'},
                    {'action': 'block_ip', 'ip': '{source.ip_address}', 'duration': 3600}
                ]
            },
            {
                'rule_id': 'suspicious_file_access',
                'name': 'Suspicious File Access',
                'description': 'Detect access to sensitive system files',
                'severity': 'CRITICAL',
                'conditions': [
                    {'field': 'event_type', 'op': '==', 'value': 'file_access'},
                    {'field': 'details.file_path', 'op': 'regex', 'pattern': r'(?i)(system32\\|etc/passwd|/etc/shadow)'}
                ],
                'actions': [
                    {'action': 'create_alert', 'severity': 'CRITICAL',
                     'message': 'Suspicious file access: {details.file_path} by {details.process_name}'},
                    {'action': 'terminate_process', 'pid': '{details.process_id}'}
                ]
            },
            {
                'rule_id': 'data_exfiltration',
                'name': 'Potential Data Exfiltration',
                'description': 'Detect large outbound data transfers',
                'severity': 'HIGH',
                'time_window': 60,  # 1 minute
                'conditions': [
                    {'field': 'event_type', 'op': '==', 'value': 'network_connection'},
                    {'field': 'details.direction', 'op': '==', 'value': 'outbound'},
                    {'field': 'details.bytes_sent', 'op': '>', 'value': 10485760},  # 10MB
                    {'field': 'details.destination.ip_address', 'op': 'not_in', 'value': ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']}
                ],
                'actions': [
                    {'action': 'create_alert', 'severity': 'HIGH',
                     'message': 'Large outbound data transfer to {details.destination.ip_address}: {details.bytes_sent} bytes'}
                ]
            }
        ]
        
        for rule_data in default_rules:
            rule = CorrelationRule.from_dict(rule_data)
            self.add_rule(rule)
    
    def add_rule(self, rule: CorrelationRule) -> bool:
        """Add a correlation rule.
        
        Args:
            rule: The correlation rule to add
            
        Returns:
            bool: True if the rule was added successfully
        """
        with self.rule_lock:
            if rule.rule_id in self.rules:
                logger.warning(f"Rule with ID {rule.rule_id} already exists")
                return False
                
            self.rules[rule.rule_id] = rule
            logger.info(f"Added correlation rule: {rule.name} (ID: {rule.rule_id})")
            return True
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            bool: True if the rule was removed successfully
        """
        with self.rule_lock:
            if rule_id not in self.rules:
                return False
                
            del self.rules[rule_id]
            logger.info(f"Removed correlation rule: {rule_id}")
            return True
    
    def _handle_security_event(self, event: SecurityEvent) -> None:
        """Handle incoming security events."""
        try:
            # Add to processing queue
            self.event_queue.put(event, block=False)
        except queue.Full:
            logger.error("Event queue is full, dropping event")
    
    def _process_events(self) -> None:
        """Background thread for processing events."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                if event is None:
                    continue
                
                # Store the event
                with self.event_store_lock:
                    self._store_event(event)
                
                # Evaluate correlation rules
                self._evaluate_rules(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
    
    def _store_event(self, event: SecurityEvent) -> None:
        """Store an event in the event store."""
        self.event_store[event.event_id] = event
        
        # Index the event for faster lookups
        for field in ['event_type', 'source.component_id', 'source.ip_address', 'source.hostname']:
            value = self._get_nested_value(event, field.split('.'))
            if value is not None:
                key = (field, str(value))
                if key not in self.event_index:
                    self.event_index[key] = set()
                self.event_index[key].add(event.event_id)
    
    def _get_nested_value(self, obj: Any, keys: List[str]) -> Any:
        """Get a nested value from a dictionary using dot notation."""
        for key in keys:
            if isinstance(obj, dict) and key in obj:
                obj = obj[key]
            else:
                return None
        return obj
    
    def _evaluate_rules(self, event: SecurityEvent) -> None:
        """Evaluate all correlation rules against an event."""
        with self.rule_lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                    
                if self._evaluate_rule(rule, event):
                    self._trigger_rule(rule, event)
    
    def _evaluate_rule(self, rule: CorrelationRule, event: SecurityEvent) -> bool:
        """Evaluate if a rule matches an event."""
        # Simple implementation - in a real SIEM, this would be more sophisticated
        # and would handle temporal correlations, counting, etc.
        
        for condition in rule.conditions:
            field = condition.get('field')
            op = condition.get('op')
            value = condition.get('value')
            
            # Get the field value from the event
            field_value = self._get_nested_value(event.to_dict(), field.split('.'))
            
            # Apply the operator
            if op == '==':
                if field_value != value:
                    return False
            elif op == '!=':
                if field_value == value:
                    return False
            elif op == '>':
                if not (field_value > value):
                    return False
            elif op == '>=':
                if not (field_value >= value):
                    return False
            elif op == '<':
                if not (field_value < value):
                    return False
            elif op == '<=':
                if not (field_value <= value):
                    return False
            elif op == 'contains':
                if value not in str(field_value):
                    return False
            elif op == 'not_contains':
                if value in str(field_value):
                    return False
            elif op == 'regex':
                pattern = condition.get('pattern')
                if pattern and not re.search(pattern, str(field_value)):
                    return False
            elif op == 'in':
                if field_value not in value:
                    return False
            elif op == 'not_in':
                if field_value in value:
                    return False
            else:
                logger.warning(f"Unsupported operator: {op}")
                return False
        
        return True
    
    def _trigger_rule(self, rule: CorrelationRule, event: SecurityEvent) -> None:
        """Trigger a rule's actions."""
        rule.last_triggered = time.time()
        rule.trigger_count += 1
        
        logger.warning(f"Rule triggered: {rule.name} (ID: {rule.rule_id})")
        
        # Execute actions
        for action in rule.actions:
            try:
                self._execute_action(action, event, rule)
            except Exception as e:
                logger.error(f"Error executing action {action}: {e}", exc_info=True)
    
    def _execute_action(self, action: Dict[str, Any], event: SecurityEvent, rule: CorrelationRule) -> None:
        """Execute a rule action."""
        action_type = action.get('action')
        
        if action_type == 'create_alert':
            self._create_alert(action, event, rule)
        elif action_type == 'block_ip':
            self._block_ip(action, event)
        elif action_type == 'terminate_process':
            self._terminate_process(action, event)
        else:
            logger.warning(f"Unsupported action type: {action_type}")
    
    def _create_alert(self, action: Dict[str, Any], event: SecurityEvent, rule: CorrelationRule) -> None:
        """Create a security alert."""
        # Format the alert message
        message = action.get('message', 'Security alert')
        try:
            message = message.format(**event.to_dict())
        except KeyError as e:
            logger.warning(f"Missing key in alert message: {e}")
        
        # Create the alert
        alert = {
            'alert_id': str(uuid.uuid4()),
            'timestamp': time.time(),
            'rule_id': rule.rule_id,
            'rule_name': rule.name,
            'severity': action.get('severity', rule.severity.name),
            'message': message,
            'event': event.to_dict(),
            'status': 'new',
            'assigned_to': None,
            'notes': []
        }
        
        # Notify alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}", exc_info=True)
        
        # Forward to SOC hub if connected
        if self.soc_hub:
            alert_event = SecurityEvent(
                event_id=alert['alert_id'],
                component=ComponentType.SIEM,
                event_type='security_alert',
                timestamp=alert['timestamp'],
                severity=EventSeverity[alert['severity']],
                details={
                    'message': alert['message'],
                    'rule_id': alert['rule_id'],
                    'rule_name': alert['rule_name']
                },
                source={
                    'component_id': 'siem-engine',
                    'hostname': 'siem-server',
                    'ip_address': '127.0.0.1'
                },
                iocs=event.iocs  # Forward any IOCs from the original event
            )
            self.soc_hub.publish_event(alert_event)
    
    def _block_ip(self, action: Dict[str, Any], event: SecurityEvent) -> None:
        """Block an IP address."""
        if not self.soc_hub:
            logger.warning("Cannot block IP: Not connected to SOC hub")
            return
            
        ip = action.get('ip')
        duration = action.get('duration', 3600)  # Default 1 hour
        
        # Format the IP using event data
        try:
            ip = ip.format(**event.to_dict())
        except KeyError as e:
            logger.warning(f"Missing key in IP format: {e}")
            return
        
        # Create a block request event
        block_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            component=ComponentType.SIEM,
            event_type='block_ip',
            timestamp=time.time(),
            severity=EventSeverity.HIGH,
            details={
                'ip_address': ip,
                'duration': duration,
                'reason': 'Blocked by SIEM rule'
            },
            source={
                'component_id': 'siem-engine',
                'hostname': 'siem-server',
                'ip_address': '127.0.0.1'
            }
        )
        
        self.soc_hub.publish_event(block_event)
    
    def _terminate_process(self, action: Dict[str, Any], event: SecurityEvent) -> None:
        """Terminate a process."""
        if not self.soc_hub:
            logger.warning("Cannot terminate process: Not connected to SOC hub")
            return
            
        pid = action.get('pid')
        
        # Format the PID using event data
        try:
            pid = pid.format(**event.to_dict())
        except KeyError as e:
            logger.warning(f"Missing key in PID format: {e}")
            return
        
        # Create a process termination event
        terminate_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            component=ComponentType.SIEM,
            event_type='terminate_process',
            timestamp=time.time(),
            severity=EventSeverity.HIGH,
            details={
                'process_id': pid,
                'reason': 'Terminated by SIEM rule'
            },
            source={
                'component_id': 'siem-engine',
                'hostname': 'siem-server',
                'ip_address': '127.0.0.1'
            }
        )
        
        self.soc_hub.publish_event(terminate_event)
    
    def add_alert_handler(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Add a handler for security alerts."""
        self.alert_handlers.append(handler)
    
    def search_events(self, query: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        """Search for events matching a query."""
        results = []
        with self.event_store_lock:
            for event in self.event_store.values():
                if self._event_matches_query(event, query):
                    results.append(event.to_dict())
                    if len(results) >= limit:
                        break
        return results
    
    def _event_matches_query(self, event: SecurityEvent, query: Dict[str, Any]) -> bool:
        """Check if an event matches a query."""
        event_dict = event.to_dict()
        
        for field, value in query.items():
            field_value = self._get_nested_value(event_dict, field.split('.'))
            if field_value != value:
                return False
                
        return True
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about rule execution."""
        stats = {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rules': []
        }
        
        for rule in self.rules.values():
            stats['rules'].append({
                'rule_id': rule.rule_id,
                'name': rule.name,
                'enabled': rule.enabled,
                'trigger_count': rule.trigger_count,
                'last_triggered': rule.last_triggered
            })
            
        return stats
    
    def stop(self) -> None:
        """Stop the SIEM engine and clean up resources."""
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
        
        # Disconnect from SOC hub if connected
        if self.soc_hub:
            self.soc_hub.unregister_component("siem-engine")
            
        logger.info("SIEM Engine stopped")
