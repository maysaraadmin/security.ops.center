"""
Threshold-based Alerting for SIEM.

This module implements threshold-based alerting on top of the threat detection engine.
It allows defining alerting rules that trigger when certain conditions are met
within a specific time window.
"""
import time
import logging
from typing import Dict, List, Any, Optional, Set, Deque, Tuple, Callable
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib
import json

logger = logging.getLogger(__name__)

class ThresholdRule:
    """Defines a threshold-based alerting rule."""
    
    def __init__(self, 
                rule_id: str,
                name: str,
                description: str,
                conditions: List[Dict[str, Any]],
                threshold: int,
                time_window: int,  # in seconds
                severity: str,
                actions: List[Dict[str, Any]],
                group_by: Optional[List[str]] = None,
                cooldown: int = 300,  # in seconds
                enabled: bool = True):
        """Initialize a threshold rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            description: Detailed description
            conditions: List of conditions that must all be met
            threshold: Number of matching events needed to trigger
            time_window: Time window in seconds to consider
            severity: Alert severity (info, low, medium, high, critical)
            actions: List of actions to take when threshold is reached
            group_by: Fields to group events by for threshold counting
            cooldown: Minimum time between alerts for the same group
            enabled: Whether the rule is enabled
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.conditions = conditions
        self.threshold = threshold
        self.time_window = time_window
        self.severity = severity
        self.actions = actions
        self.group_by = group_by or []
        self.cooldown = cooldown
        self.enabled = enabled
        
        # State tracking
        self.event_window: Dict[str, Deque[Tuple[float, Dict[str, Any]]]] = defaultdict(deque)
        self.last_alert_time: Dict[str, float] = {}
        self.metrics = {
            'evaluations': 0,
            'matches': 0,
            'alerts_triggered': 0,
            'last_triggered': None
        }
    
    def get_group_key(self, event: Dict[str, Any]) -> str:
        """Generate a group key based on the group_by fields."""
        if not self.group_by:
            return 'default'
        
        key_parts = []
        for field in self.group_by:
            # Handle nested fields with dot notation
            value = event
            for part in field.split('.'):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    value = ''
                    break
            key_parts.append(str(value))
        
        return ':'.join(key_parts)
    
    def matches_conditions(self, event: Dict[str, Any]) -> bool:
        """Check if an event matches all conditions."""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, event):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluate a single condition against an event."""
        for field, expected in condition.items():
            # Skip internal fields
            if field.startswith('_'):
                continue
                
            # Get the actual value from the event
            actual = self._get_nested_value(event, field)
            
            # Handle different comparison operators
            if field.endswith('_regex'):
                if not re.search(re.compile(expected, re.IGNORECASE), str(actual or '')):
                    return False
            elif field.endswith('_gt'):
                if not self._compare_values(actual, expected, '>'):
                    return False
            elif field.endswith('_gte'):
                if not self._compare_values(actual, expected, '>='):
                    return False
            elif field.endswith('_lt'):
                if not self._compare_values(actual, expected, '<'):
                    return False
            elif field.endswith('_lte'):
                if not self._compare_values(actual, expected, '<='):
                    return False
            elif field.endswith('_in'):
                if actual not in expected:
                    return False
            elif field.endswith('_contains'):
                if expected not in str(actual):
                    return False
            elif field.endswith('_exists'):
                if bool(actual) != expected:
                    return False
            else:
                # Default to equality comparison
                if actual != expected:
                    return False
        
        return True
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str, default: Any = None) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        keys = path.split('.')
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def _compare_values(self, actual: Any, expected: Any, operator: str) -> bool:
        """Compare two values using the specified operator."""
        try:
            # Try numeric comparison first
            actual_num = float(actual)
            expected_num = float(expected)
            
            if operator == '>':
                return actual_num > expected_num
            elif operator == '>=':
                return actual_num >= expected_num
            elif operator == '<':
                return actual_num < expected_num
            elif operator == '<=':
                return actual_num <= expected_num
            
        except (ValueError, TypeError):
            # Fall back to string comparison
            actual_str = str(actual or '')
            expected_str = str(expected or '')
            
            if operator == '>':
                return actual_str > expected_str
            elif operator == '>=':
                return actual_str >= expected_str
            elif operator == '<':
                return actual_str < expected_str
            elif operator == '<=':
                return actual_str <= expected_str
        
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event and check if it triggers any alerts.
        
        Returns:
            List of actions to take if threshold is reached, empty list otherwise
        """
        if not self.enabled:
            return []
        
        self.metrics['evaluations'] += 1
        
        # Check if event matches all conditions
        if not self.matches_conditions(event):
            return []
        
        # Get the group key for this event
        group_key = self.get_group_key(event)
        
        # Add event to the window for this group
        current_time = time.time()
        self.event_window[group_key].append((current_time, event))
        
        # Remove events outside the time window
        while (self.event_window[group_key] and 
               current_time - self.event_window[group_key][0][0] > self.time_window):
            self.event_window[group_key].popleft()
        
        # Check if we've reached the threshold
        if len(self.event_window[group_key]) >= self.threshold:
            # Check cooldown
            last_alert = self.last_alert_time.get(group_key, 0)
            if current_time - last_alert >= self.cooldown:
                self.metrics['matches'] += 1
                self.metrics['alerts_triggered'] += 1
                self.metrics['last_triggered'] = datetime.utcnow().isoformat()
                self.last_alert_time[group_key] = current_time
                
                # Prepare alert context
                alert_context = {
                    'rule_id': self.id,
                    'rule_name': self.name,
                    'severity': self.severity,
                    'event_count': len(self.event_window[group_key]),
                    'time_window_seconds': self.time_window,
                    'group_key': group_key if group_key != 'default' else None,
                    'first_event': self.event_window[group_key][0][1] if self.event_window[group_key] else None,
                    'last_event': self.event_window[group_key][-1][1] if self.event_window[group_key] else None,
                    'all_events': [e[1] for e in self.event_window[group_key]]
                }
                
                # Return actions with alert context
                return [
                    {**action, 'context': {**action.get('context', {}), **alert_context}}
                    for action in self.actions
                ]
        
        return []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'severity': self.severity,
            'actions': self.actions,
            'group_by': self.group_by,
            'cooldown': self.cooldown,
            'enabled': self.enabled,
            'metrics': self.metrics
        }


class ThresholdAlertManager:
    """Manages threshold-based alerting rules and event processing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threshold alert manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rules: Dict[str, ThresholdRule] = {}
        self.rule_files = self.config.get('rule_files', [])
        self.rule_dir = self.config.get('rule_dir', 'threshold_rules')
        
        # Load rules from configuration
        self._load_rules()
    
    def add_rule(self, rule: ThresholdRule) -> None:
        """Add a threshold rule to the manager."""
        self.rules[rule.id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a threshold rule.
        
        Returns:
            True if the rule was removed, False if it didn't exist
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a threshold rule.
        
        Returns:
            True if the rule was enabled, False if it didn't exist
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a threshold rule.
        
        Returns:
            True if the rule was disabled, False if it didn't exist
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through all threshold rules.
        
        Returns:
            List of all actions that were triggered
        """
        all_actions = []
        
        for rule in self.rules.values():
            try:
                actions = rule.process_event(event)
                all_actions.extend(actions)
            except Exception as e:
                logger.error(f"Error processing event with rule {rule.id}: {e}", exc_info=True)
        
        return all_actions
    
    def _load_rules(self) -> None:
        """Load threshold rules from configuration files."""
        # This would load rules from files in the rule_dir
        # Implementation depends on your configuration management
        pass
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about rule processing."""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rules': [
                {
                    'id': rule.id,
                    'name': rule.name,
                    'enabled': rule.enabled,
                    'metrics': rule.metrics
                }
                for rule in self.rules.values()
            ]
        }
