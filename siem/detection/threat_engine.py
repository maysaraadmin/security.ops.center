"""
Threat Detection Engine for SIEM.

This module implements a rule-based threat detection engine that can identify
potential security threats from events and logs.
"""
import re
import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Pattern, Union, Set
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ThreatRule:
    """Represents a single threat detection rule."""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                severity: str, category: str, 
                condition: Dict[str, Any], actions: List[Dict[str, Any]],
                priority: int = 0, enabled: bool = True, tags: List[str] = None):
        """Initialize a threat rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name of the rule
            description: Detailed description of the threat
            severity: Severity level (info, low, medium, high, critical)
            category: Threat category (e.g., 'brute_force', 'malware', 'data_exfiltration')
            condition: Dictionary defining the rule's matching conditions
            actions: List of actions to take when the rule matches
            priority: Rule priority (higher numbers are evaluated first)
            enabled: Whether the rule is enabled
            tags: List of tags for categorization
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.severity = severity.lower()
        self.category = category
        self.condition = condition
        self.actions = actions
        self.priority = priority
        self.enabled = enabled
        self.tags = set(tags or [])
        self.compiled_patterns = self._compile_patterns(condition)
        self.metrics = {
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
                self.metrics['matches'] += 1
                self.metrics['last_matched'] = datetime.utcnow()
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
            'severity': self.severity,
            'category': self.category,
            'condition': self.condition,
            'actions': self.actions,
            'priority': self.priority,
            'enabled': self.enabled,
            'tags': list(self.tags),
            'metrics': self.metrics
        }


class ThreatEngine:
    """Rule-based threat detection engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threat engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rules: Dict[str, ThreatRule] = {}
        self.rule_files = self.config.get('rule_files', [])
        self.rule_dir = self.config.get('rule_dir', 'rules')
        self.rule_ext = self.config.get('rule_ext', '.json')
        self.action_handlers = {
            'alert': self._handle_alert,
            'log': self._handle_log,
            'block': self._handle_block,
            'throttle': self._handle_throttle,
            'enrich': self._handle_enrich,
            'correlate': self._handle_correlate
        }
    
    def load_rules(self, force: bool = False) -> None:
        """Load threat detection rules from files.
        
        Args:
            force: If True, reload all rules even if they haven't changed
        """
        # Implementation would load rules from files
        pass
    
    def add_rule(self, rule: ThreatRule) -> None:
        """Add a rule to the engine."""
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
        """Process an event through all active rules.
        
        Returns:
            List of actions that were triggered
        """
        triggered_actions = []
        
        # Process event against all rules, sorted by priority (highest first)
        for rule in sorted(self.rules.values(), 
                          key=lambda r: r.priority, 
                          reverse=True):
            if rule.match(event):
                # Add rule context to the event
                event['threat'] = {
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'category': rule.category,
                    'description': rule.description
                }
                
                # Execute rule actions
                for action in rule.actions:
                    action_result = self._execute_action(action, event)
                    triggered_actions.append({
                        'rule_id': rule.id,
                        'action': action,
                        'result': action_result
                    })
        
        return triggered_actions
    
    def _execute_action(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an action."""
        action_type = action.get('type')
        handler = self.action_handlers.get(action_type)
        
        if not handler:
            logger.warning(f"Unknown action type: {action_type}")
            return {'status': 'error', 'message': f'Unknown action type: {action_type}'}
        
        try:
            return handler(action, event)
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    def _handle_alert(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an alert action."""
        # Implementation would send an alert
        return {'status': 'success', 'message': 'Alert sent'}
    
    def _handle_log(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a log action."""
        # Implementation would log the event
        return {'status': 'success', 'message': 'Event logged'}
    
    def _handle_block(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a block action."""
        # Implementation would block the source
        return {'status': 'success', 'message': 'Source blocked'}
    
    def _handle_throttle(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a throttle action."""
        # Implementation would throttle the source
        return {'status': 'success', 'message': 'Source throttled'}
    
    def _handle_enrich(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an enrich action."""
        # Implementation would enrich the event
        return {'status': 'success', 'message': 'Event enriched'}
    
    def _handle_correlate(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a correlate action."""
        # Implementation would correlate with other events
        return {'status': 'success', 'message': 'Event correlated'}
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the engine."""
        return {
            'status': 'running',
            'rules_loaded': len(self.rules),
            'rules_enabled': sum(1 for r in self.rules.values() if r.enabled),
            'rules_matched': sum(r.metrics['matches'] for r in self.rules.values())
        }
