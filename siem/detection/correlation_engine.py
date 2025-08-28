"""
Correlation Engine for SIEM.

This module implements a rule-based correlation engine for detecting security events.
"""
import re
import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Pattern, Union
from datetime import datetime, timedelta

# Try absolute import first, fall back to relative if needed
try:
    from siem.core.component import Component
except ImportError:
    from ..core.component import Component

logger = logging.getLogger(__name__)

class CorrelationRule:
    """Represents a single correlation rule."""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                condition: Dict[str, Any], actions: List[Dict[str, Any]], 
                priority: int = 0, enabled: bool = True):
        """Initialize a correlation rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name of the rule
            description: Detailed description of what the rule detects
            condition: Dictionary defining the rule's matching conditions
            actions: List of actions to take when the rule matches
            priority: Rule priority (higher numbers are evaluated first)
            enabled: Whether the rule is enabled
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.condition = condition
        self.actions = actions
        self.priority = priority
        self.enabled = enabled
        self.compiled_patterns = self._compile_patterns(condition)
    
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
            return self._evaluate_condition(self.condition, event)
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
                
            # Get the actual value from the event using dot notation (e.g., 'source.ip')
            actual = self._get_nested_value(event, field)
            
            # Handle different comparison operators
            if field.endswith('_regex'):
                pattern = self.compiled_patterns.get(field)
                if pattern and not re.search(pattern, str(actual or '')):
                    return False
            elif field.endswith('_gt'):
                try:
                    if not (float(actual) > float(expected)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif field.endswith('_lt'):
                try:
                    if not (float(actual) < float(expected)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif field.endswith('_gte'):
                try:
                    if not (float(actual) >= float(expected)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif field.endswith('_lte'):
                try:
                    if not (float(actual) <= float(expected)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif field.endswith('_exists'):
                if expected and actual is None:
                    return False
                if not expected and actual is not None:
                    return False
            elif field.endswith('_in'):
                if actual not in expected:
                    return False
            elif field.endswith('_contains'):
                if expected not in str(actual):
                    return False
            elif field.endswith('_startswith'):
                if not str(actual).startswith(str(expected)):
                    return False
            elif field.endswith('_endswith'):
                if not str(actual).endswith(str(expected)):
                    return False
            elif isinstance(expected, dict):
                # Nested condition
                if not self._evaluate_condition(expected, actual or {}):
                    return False
            elif actual != expected:
                return False
        
        return True
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if key.endswith(('_gt', '_lt', '_gte', '_lte', '_exists', '_in', 
                           '_contains', '_startswith', '_endswith', '_regex')):
                key = key.rsplit('_', 1)[0]
                
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif hasattr(value, key):
                value = getattr(value, key)
            else:
                return None
                
        return value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'condition': self.condition,
            'actions': self.actions,
            'priority': self.priority,
            'enabled': self.enabled
        }
    
    @classmethod
    def from_dict(cls, rule_dict: Dict[str, Any]) -> 'CorrelationRule':
        """Create a rule from a dictionary."""
        return cls(
            rule_id=rule_dict['id'],
            name=rule_dict.get('name', ''),
            description=rule_dict.get('description', ''),
            condition=rule_dict['condition'],
            actions=rule_dict.get('actions', []),
            priority=rule_dict.get('priority', 0),
            enabled=rule_dict.get('enabled', True)
        )


class CorrelationEngine(Component):
    """Rule-based correlation engine for detecting security events."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the correlation engine.
        
        Args:
            config: Configuration dictionary
        """
        super().__init__(config or {})
        self.rules: Dict[str, CorrelationRule] = {}
        self.rule_files = self.config.get('rule_files', [])
        self.rule_dir = self.config.get('rule_dir', 'rules')
        self.rule_ext = self.config.get('rule_ext', '.json')
        self.last_modified: Dict[str, float] = {}
        self.action_handlers = {
            'alert': self._handle_alert,
            'log': self._handle_log,
            'block': self._handle_block,
            'throttle': self._handle_throttle
        }
    
    def initialize(self) -> None:
        """Initialize the correlation engine."""
        super().initialize()
        self.load_rules()
    
    def load_rules(self, force: bool = False) -> None:
        """Load correlation rules from files.
        
        Args:
            force: If True, reload all rules even if they haven't changed
        """
        import os
        import glob
        
        # Get all rule files
        rule_files = set()
        
        # Add explicit rule files
        for rule_file in self.rule_files:
            if os.path.isfile(rule_file):
                rule_files.add(os.path.abspath(rule_file))
        
        # Add files from rule directory
        if os.path.isdir(self.rule_dir):
            pattern = os.path.join(self.rule_dir, f'*{self.rule_ext}')
            rule_files.update(glob.glob(pattern))
        
        # Check for modified files
        for rule_file in rule_files:
            try:
                mtime = os.path.getmtime(rule_file)
                
                if force or rule_file not in self.last_modified or mtime > self.last_modified[rule_file]:
                    self._load_rule_file(rule_file)
                    self.last_modified[rule_file] = mtime
                    
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}", exc_info=True)
    
    def _load_rule_file(self, file_path: str) -> None:
        """Load rules from a single file."""
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            if isinstance(rules_data, dict):
                rules_data = [rules_data]
                
            for rule_data in rules_data:
                try:
                    rule = CorrelationRule.from_dict(rule_data)
                    self.rules[rule.id] = rule
                    logger.info(f"Loaded rule: {rule.name} (ID: {rule.id})")
                except Exception as e:
                    logger.error(f"Error loading rule from {file_path}: {e}", exc_info=True)
                    
        except Exception as e:
            logger.error(f"Error reading rule file {file_path}: {e}", exc_info=True)
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through the correlation engine.
        
        Args:
            event: The event to process
            
        Returns:
            List of actions that were triggered
        """
        triggered_actions = []
        
        # Sort rules by priority (highest first)
        sorted_rules = sorted(self.rules.values(), key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            if rule.match(event):
                logger.info(f"Rule matched: {rule.name} (ID: {rule.id})")
                
                # Execute all actions for this rule
                for action in rule.actions:
                    action_type = action.get('type')
                    if action_type in self.action_handlers:
                        try:
                            result = self.action_handlers[action_type](event, action)
                            if result:
                                result.update({
                                    'rule_id': rule.id,
                                    'rule_name': rule.name,
                                    'action_type': action_type
                                })
                                triggered_actions.append(result)
                        except Exception as e:
                            logger.error(f"Error executing action {action_type}: {e}", exc_info=True)
        
        return triggered_actions
    
    def _handle_alert(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an alert action."""
        alert = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': event,
            'severity': action.get('severity', 'medium'),
            'message': action.get('message', 'Security alert triggered'),
            'tags': action.get('tags', [])
        }
        
        logger.warning(f"ALERT: {alert['message']} (Severity: {alert['severity']})")
        return alert
    
    def _handle_log(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a log action."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': event,
            'message': action.get('message', 'Rule matched'),
            'level': action.get('level', 'info')
        }
        
        logger.info(f"LOG: {log_entry['message']}")
        return log_entry
    
    def _handle_block(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a block action."""
        # In a real implementation, this would block the source IP
        source_ip = event.get('source', {}).get('ip')
        
        if source_ip:
            logger.warning(f"BLOCK: Blocking IP {source_ip} - {action.get('reason', 'Suspicious activity')}")
            
            return {
                'action': 'block',
                'source_ip': source_ip,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'reason': action.get('reason', 'Suspicious activity'),
                'duration': action.get('duration', 3600)  # Default: 1 hour
            }
        
        return {}
    
    def _handle_throttle(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a throttle action."""
        # In a real implementation, this would throttle the source IP
        source_ip = event.get('source', {}).get('ip')
        
        if source_ip:
            logger.warning(f"THROTTLE: Throttling IP {source_ip} - {action.get('reason', 'Too many requests')}")
            
            return {
                'action': 'throttle',
                'source_ip': source_ip,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'reason': action.get('reason', 'Too many requests'),
                'rate_limit': action.get('rate_limit', '10/60s'),  # Default: 10 requests per minute
                'duration': action.get('duration', 3600)  # Default: 1 hour
            }
        
        return {}
    
    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        """Get a rule by ID."""
        return self.rules.get(rule_id)
    
    def add_rule(self, rule: CorrelationRule) -> None:
        """Add or update a rule."""
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
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules as dictionaries."""
        return [rule.to_dict() for rule in self.rules.values()]
    
    def clear_rules(self) -> None:
        """Remove all rules."""
        self.rules.clear()
    
    def status(self) -> Dict[str, Any]:
        """Get the status of the correlation engine."""
        return {
            'enabled': self._initialized,
            'rule_count': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rule_files': list(self.last_modified.keys())
        }
