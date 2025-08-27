"""
Base classes for incident response actions in SIEM.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Type, TypeVar
import logging
from datetime import datetime, timedelta
import json

class ResponseAction(ABC):
    """Abstract base class for all response actions."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the response action."""
        self.config = config or {}
        self.action_id = self.config.get('id', self.__class__.__name__)
        self.name = self.config.get('name', self.action_id)
        self.enabled = self.config.get('enabled', True)
        self.logger = logging.getLogger(f"siem.response.{self.action_id}")
        self._setup()
    
    @abstractmethod
    def _setup(self) -> None:
        """Perform any necessary setup for the action."""
        pass
    
    @abstractmethod
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the response action.
        
        Args:
            alert: The alert that triggered this action
            
        Returns:
            Dictionary with action results
        """
        pass
    
    def _log_action(self, action_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Create a standardized action log entry."""
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': {
                'kind': 'alert',
                'category': 'response',
                'type': [action_type],
                'outcome': details.get('success', False) and 'success' or 'failure',
                'reason': details.get('message', '')
            },
            'action': {
                'id': self.action_id,
                'name': self.name,
                'type': self.__class__.__name__,
                'target': details.get('target', {})
            },
            'message': f"Response action '{self.name}' executed: {details.get('message', '')}",
            'tags': ['siem', 'response', action_type]
        }


class ResponseRule:
    """Defines when and how to respond to alerts."""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        conditions: List[Dict[str, Any]],
        actions: List[Dict[str, Any]],
        enabled: bool = True
    ):
        """Initialize the response rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            conditions: List of conditions that must be met
            actions: List of actions to execute when conditions are met
            enabled: Whether the rule is enabled
        """
        self.rule_id = rule_id
        self.name = name
        self.conditions = conditions
        self.actions = actions
        self.enabled = enabled
        self.logger = logging.getLogger(f"siem.response.rule.{rule_id}")
    
    def matches(self, alert: Dict[str, Any]) -> bool:
        """Check if the alert matches this rule's conditions."""
        if not self.enabled:
            return False
            
        for condition in self.conditions:
            field = condition.get('field')
            operator = condition.get('operator', 'equals')
            value = condition.get('value')
            
            # Get the field value using dot notation (e.g., 'event.severity')
            field_value = self._get_nested_value(alert, field)
            
            # Apply the operator
            if operator == 'equals' and field_value != value:
                return False
            elif operator == 'contains' and value not in str(field_value):
                return False
            elif operator == 'starts_with' and not str(field_value).startswith(str(value)):
                return False
            elif operator == 'ends_with' and not str(field_value).endswith(str(value)):
                return False
            elif operator == 'greater_than' and not (isinstance(field_value, (int, float)) and field_value > value):
                return False
            elif operator == 'less_than' and not (isinstance(field_value, (int, float)) and field_value < value):
                return False
            elif operator == 'exists' and field_value is None:
                return False
            
        return True
    
    def _get_nested_value(self, obj: Dict[str, Any], field_path: str) -> Any:
        """Get a nested value from a dictionary using dot notation."""
        if not field_path:
            return None
            
        keys = field_path.split('.')
        value = obj
        
        try:
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                elif hasattr(value, key):
                    value = getattr(value, key)
                else:
                    return None
            return value
        except (KeyError, AttributeError, TypeError):
            return None
