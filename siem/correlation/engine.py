"""
Correlation Engine for SIEM.

This module implements a real-time event correlation engine that can detect
complex patterns across multiple events.
"""
import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Set, Tuple, Union, Pattern
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib

logger = logging.getLogger(__name__)

class CorrelationRule:
    """Represents a single correlation rule."""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                condition: Dict[str, Any], actions: List[Dict[str, Any]],
                priority: int = 0, enabled: bool = True, tags: List[str] = None):
        """Initialize a correlation rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name of the rule
            description: Description of what the rule detects
            condition: Dictionary defining the rule's matching conditions
            actions: List of actions to take when the rule matches
            priority: Rule priority (higher numbers are evaluated first)
            enabled: Whether the rule is enabled
            tags: List of tags for categorization
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.condition = condition
        self.actions = actions
        self.priority = priority
        self.enabled = enabled
        self.tags = set(tags or [])
        self.compiled_patterns = self._compile_patterns(condition)
        self.stats = {
            'matches': 0,
            'last_matched': None,
            'created_at': datetime.utcnow()
        }
    
    def _compile_patterns(self, condition: Dict[str, Any]) -> Dict[str, Union[Pattern, Any]]:
        """Compile regex patterns for the rule conditions."""
        compiled = {}
        for key, value in condition.items():
            if key.endswith('_regex') and isinstance(value, str):
                try:
                    compiled[key] = re.compile(value, re.IGNORECASE)
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in rule {self.id}: {value} - {e}")
                    compiled[key] = None
            elif isinstance(value, dict):
                # Recursively compile patterns in nested conditions
                compiled.update(self._compile_patterns(value))
        return compiled
    
    def match(self, event: Dict[str, Any]) -> bool:
        """Check if an event matches this rule's conditions."""
        if not self.enabled:
            return False
        
        try:
            matches = self._evaluate_condition(self.condition, event)
            if matches:
                self.stats['matches'] += 1
                self.stats['last_matched'] = datetime.utcnow()
            return matches
        except Exception as e:
            logger.error(f"Error evaluating rule {self.id}: {e}", exc_info=True)
            return False
    
    def _evaluate_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Recursively evaluate a condition against an event."""
        # Handle logical operators
        if 'and' in condition:
            return all(self._evaluate_condition(c, event) for c in condition['and'])
        elif 'or' in condition:
            return any(self._evaluate_condition(c, event) for c in condition['or'])
        elif 'not' in condition:
            return not self._evaluate_condition(condition['not'], event)
        
        # Handle field comparisons
        for field, expected in condition.items():
            if field.startswith('_'):  # Skip internal fields
                continue
                
            # Get the actual value from the event using dot notation
            actual = self._get_nested_value(event, field)
            
            # Handle different comparison operators
            if field.endswith('_regex'):
                pattern = self.compiled_patterns.get(field)
                if pattern and not re.search(pattern, str(actual or '')):
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
        if not path or not isinstance(obj, dict):
            return default
            
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
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'condition': self.condition,
            'actions': self.actions,
            'priority': self.priority,
            'enabled': self.enabled,
            'tags': list(self.tags),
            'stats': {
                'matches': self.stats['matches'],
                'last_matched': self.stats['last_matched'].isoformat() if self.stats['last_matched'] else None,
                'created_at': self.stats['created_at'].isoformat()
            }
        }


class CorrelationEngine:
    """Real-time event correlation engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the correlation engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rules: Dict[str, CorrelationRule] = {}
        self.rule_files = self.config.get('rule_files', [])
        self.rule_dir = self.config.get('rule_dir', 'rules')
        self.rule_ext = self.config.get('rule_ext', '.json')
        self.action_handlers = {
            'alert': self._handle_alert,
            'log': self._handle_log,
            'enrich': self._handle_enrich,
            'correlate': self._handle_correlate,
            'throttle': self._handle_throttle,
            'block': self._handle_block
        }
        
        # For complex event processing
        self.event_windows: Dict[str, Dict[Any, deque]] = defaultdict(lambda: defaultdict(deque))
        self.correlation_windows: Dict[str, Dict[Any, Dict[str, Any]]] = defaultdict(dict)
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'rules_triggered': 0,
            'start_time': datetime.utcnow().isoformat(),
            'last_processed': None
        }
    
    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule to the engine."""
        self.rules[rule.id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID.
        
        Returns:
            True if the rule was removed, False if it didn't exist
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID.
        
        Returns:
            True if the rule was enabled, False if it didn't exist
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID.
        
        Returns:
            True if the rule was disabled, False if it didn't exist
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through the correlation engine.
        
        Args:
            event: The event to process
            
        Returns:
            List of actions that were triggered
        """
        self.stats['events_processed'] += 1
        self.stats['last_processed'] = datetime.utcnow().isoformat()
        
        triggered_actions = []
        
        # Process event against all rules, sorted by priority (highest first)
        for rule in sorted(self.rules.values(), 
                          key=lambda r: r.priority, 
                          reverse=True):
            if rule.match(event):
                self.stats['rules_triggered'] += 1
                
                # Execute rule actions
                for action in rule.actions:
                    action_result = self._execute_action(action, event, rule)
                    if action_result:
                        triggered_actions.append({
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'action': action,
                            'result': action_result
                        })
        
        # Process complex event patterns
        self._process_complex_events(event)
        
        return triggered_actions
    
    def _process_complex_events(self, event: Dict[str, Any]) -> None:
        """Process events for complex event patterns."""
        # This is a placeholder for complex event processing logic
        # In a real implementation, this would:
        # 1. Add events to sliding time windows
        # 2. Check for patterns across multiple events
        # 3. Trigger actions when patterns are matched
        pass
    
    def _execute_action(self, action: Dict[str, Any], 
                       event: Dict[str, Any], 
                       rule: CorrelationRule) -> Dict[str, Any]:
        """Execute an action."""
        action_type = action.get('type')
        handler = self.action_handlers.get(action_type)
        
        if not handler:
            logger.warning(f"Unknown action type: {action_type}")
            return {'status': 'error', 'message': f'Unknown action type: {action_type}'}
        
        try:
            return handler(action, event, rule)
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    def _handle_alert(self, action: Dict[str, Any], 
                     event: Dict[str, Any], 
                     rule: CorrelationRule) -> Dict[str, Any]:
        """Handle an alert action."""
        # Implementation would send an alert
        alert = {
            'id': hashlib.md5(f"{event.get('@timestamp')}-{rule.id}".encode()).hexdigest(),
            'timestamp': datetime.utcnow().isoformat(),
            'rule': {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'priority': rule.priority
            },
            'event': event,
            'severity': action.get('severity', 'medium'),
            'message': action.get('message', f"Rule {rule.name} triggered")
        }
        
        # Add custom fields from action
        if 'fields' in action:
            alert.update(action['fields'])
        
        logger.info(f"ALERT: {alert['message']}")
        return {'status': 'success', 'alert': alert}
    
    def _handle_log(self, action: Dict[str, Any], 
                   event: Dict[str, Any], 
                   rule: CorrelationRule) -> Dict[str, Any]:
        """Handle a log action."""
        message = action.get('message', f"Rule {rule.name} matched")
        logger.info(f"LOG: {message}")
        return {'status': 'success', 'message': message}
    
    def _handle_enrich(self, action: Dict[str, Any], 
                      event: Dict[str, Any], 
                      rule: CorrelationRule) -> Dict[str, Any]:
        """Handle an enrich action."""
        # Implementation would enrich the event with additional data
        field = action.get('field', 'enriched')
        value = action.get('value', True)
        
        # Add the enrichment to the event
        if field not in event:
            event[field] = value
        
        return {'status': 'success', 'enriched': field}
    
    def _handle_correlate(self, action: Dict[str, Any], 
                         event: Dict[str, Any], 
                         rule: CorrelationRule) -> Dict[str, Any]:
        """Handle a correlate action."""
        # Implementation would correlate this event with others
        correlation_key = action.get('key', 'default')
        window_size = action.get('window', 60)  # seconds
        
        # Add to correlation window
        current_time = time.time()
        window = self.correlation_windows.get(correlation_key, {})
        
        # Clean up old events
        window = {k: v for k, v in window.items() if current_time - v['timestamp'] <= window_size}
        
        # Add current event
        event_key = f"{event.get('@timestamp')}-{rule.id}"
        window[event_key] = {
            'event': event,
            'timestamp': current_time,
            'rule_id': rule.id
        }
        
        # Check for correlation conditions
        if len(window) >= action.get('threshold', 1):
            # Trigger correlation action
            return {
                'status': 'correlated',
                'count': len(window),
                'events': list(window.values())
            }
        
        self.correlation_windows[correlation_key] = window
        return {'status': 'pending', 'count': len(window)}
    
    def _handle_throttle(self, action: Dict[str, Any], 
                        event: Dict[str, Any], 
                        rule: CorrelationRule) -> Dict[str, Any]:
        """Handle a throttle action."""
        # Implementation would throttle the source
        source = event.get('source', {}).get('ip', 'unknown')
        logger.info(f"THROTTLE: Throttling source {source}")
        return {'status': 'success', 'source': source}
    
    def _handle_block(self, action: Dict[str, Any], 
                     event: Dict[str, Any], 
                     rule: CorrelationRule) -> Dict[str, Any]:
        """Handle a block action."""
        # Implementation would block the source
        source = event.get('source', {}).get('ip', 'unknown')
        logger.warning(f"BLOCK: Blocking source {source}")
        return {'status': 'success', 'source': source, 'blocked': True}
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the correlation engine."""
        return {
            'status': 'running',
            'rules_loaded': len(self.rules),
            'rules_enabled': sum(1 for r in self.rules.values() if r.enabled),
            'stats': {
                'events_processed': self.stats['events_processed'],
                'rules_triggered': self.stats['rules_triggered'],
                'start_time': self.stats['start_time'],
                'last_processed': self.stats['last_processed']
            }
        }
