"""
Correlation Engine for SIEM.
Processes events through correlation rules to detect security incidents.
"""
import logging
from typing import Dict, List, Any, Type, Optional, TypeVar
from datetime import datetime
import importlib
import pkgutil
import inspect

from .base import CorrelationRule, EventProcessor

RuleClass = TypeVar('RuleClass', bound=CorrelationRule)

class CorrelationEngine(EventProcessor):
    """Processes events through correlation rules to detect security incidents."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the correlation engine."""
        super().__init__(config or {})
        self.rules: Dict[str, CorrelationRule] = {}
        self._load_builtin_rules()
    
    def _load_builtin_rules(self) -> None:
        """Load built-in correlation rules."""
        try:
            # Import the rules module to get all rule classes
            from . import rules
            
            # Find all rule classes in the rules module
            for name, obj in inspect.getmembers(rules):
                if (
                    inspect.isclass(obj) 
                    and issubclass(obj, CorrelationRule) 
                    and obj != CorrelationRule  # Don't include the base class
                ):
                    self.add_rule(obj, {})
                    
            self.logger.info(f"Loaded {len(self.rules)} built-in correlation rules")
                    
        except Exception as e:
            self.logger.error(f"Failed to load built-in rules: {e}")
    
    def add_rule(self, rule_class: Type[RuleClass], config: Dict[str, Any]) -> str:
        """Add a correlation rule.
        
        Args:
            rule_class: The rule class to add
            config: Configuration for the rule
            
        Returns:
            The ID of the added rule
        """
        try:
            rule = rule_class(config)
            rule_id = rule.rule_id
            self.rules[rule_id] = rule
            self.logger.info(f"Added correlation rule: {rule_id}")
            return rule_id
        except Exception as e:
            self.logger.error(f"Failed to add rule {rule_class.__name__}: {e}")
            raise
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            True if the rule was removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.logger.info(f"Removed correlation rule: {rule_id}")
            return True
        return False
    
    def process(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through all correlation rules.
        
        Args:
            event: The event to process
            
        Returns:
            List of generated alerts (may be empty)
        """
        alerts = []
        
        # Skip if event is already an alert
        if event.get('event', {}).get('kind') == 'alert':
            return []
        
        # Process event through each rule
        for rule_id, rule in list(self.rules.items()):
            try:
                alert = rule.add_event(event)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                self.logger.error(
                    f"Error processing event with rule {rule_id}: {e}",
                    exc_info=True
                )
        
        return alerts
    
    def batch_process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of events through all correlation rules.
        
        Args:
            events: List of events to process
            
        Returns:
            List of generated alerts
        """
        alerts = []
        for event in events:
            alerts.extend(self.process(event))
        return alerts
    
    def get_rule_status(self) -> List[Dict[str, Any]]:
        """Get status of all rules.
        
        Returns:
            List of rule status dictionaries
        """
        status = []
        for rule_id, rule in self.rules.items():
            status.append({
                'id': rule_id,
                'description': rule.description,
                'severity': rule.severity,
                'event_count': len(rule.events),
                'window_seconds': rule.window.total_seconds(),
                'threshold': rule.threshold
            })
        return status
