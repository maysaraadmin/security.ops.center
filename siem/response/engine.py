"""
Incident Response Engine for SIEM.
Manages and executes response actions based on alerts.
"""
import logging
from typing import Dict, Any, List, Type, Optional, TypeVar
import importlib
import inspect
from datetime import datetime, timedelta
import threading
import time

from .base import ResponseAction, ResponseRule
from .enhanced_actions import ACTIONS as ENHANCED_ACTIONS

# Type variable for ResponseAction subclasses
ActionClass = TypeVar('ActionClass', bound=ResponseAction)

class ResponseEngine:
    """
    Manages and executes response actions based on alerts.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the response engine."""
        self.config = config or {}
        self.logger = logging.getLogger("siem.response.engine")
        
        # Store actions and rules
        self.actions: Dict[str, ResponseAction] = {}
        self.rules: Dict[str, ResponseRule] = {}
        
        # Action execution queue
        self.action_queue = []
        self.queue_lock = threading.Lock()
        self.stop_event = threading.Event()
        
        # Start the action processor thread
        self.processor_thread = threading.Thread(
            target=self._process_actions,
            daemon=True
        )
        self.processor_thread.start()
        
        # Load built-in and enhanced actions and rules
        self._load_builtin_actions()
        self._load_enhanced_actions()
        self._load_rules()
    
    def _load_enhanced_actions(self) -> None:
        """Load enhanced response actions."""
        for name, action_class in ENHANCED_ACTIONS.items():
            try:
                action_instance = action_class(self.config.get('actions', {}).get(name, {}))
                self.actions[name] = action_instance
                self.logger.info(f"Loaded enhanced action: {name}")
            except Exception as e:
                self.logger.error(f"Failed to load enhanced action {name}: {str(e)}", exc_info=True)
    
    def _load_builtin_actions(self) -> None:
        """Load built-in response actions."""
        try:
            # Import the actions module to get all action classes
            from . import actions
            
            # Find all action classes in the module
            for name, obj in inspect.getmembers(actions):
                if (
                    inspect.isclass(obj) 
                    and issubclass(obj, ResponseAction) 
                    and obj != ResponseAction  # Don't include the base class
                ):
                    # Create an instance with default config
                    self.add_action(obj, {})
            
            self.logger.info(f"Loaded {len(self.actions)} built-in response actions")
                    
        except Exception as e:
            self.logger.error(f"Failed to load built-in actions: {e}")
    
    def _load_rules(self) -> None:
        """Load response rules from configuration."""
        rules_config = self.config.get('rules', [])
        
        for rule_config in rules_config:
            try:
                rule = ResponseRule(
                    rule_id=rule_config['id'],
                    name=rule_config.get('name', rule_config['id']),
                    conditions=rule_config.get('conditions', []),
                    actions=rule_config.get('actions', []),
                    enabled=rule_config.get('enabled', True)
                )
                self.rules[rule.rule_id] = rule
                self.logger.info(f"Loaded response rule: {rule.rule_id}")
            except Exception as e:
                self.logger.error(f"Failed to load rule {rule_config.get('id')}: {e}")
    
    def add_action(
        self, 
        action_class: Type[ActionClass], 
        config: Dict[str, Any]
    ) -> str:
        """
        Add a response action to the engine.
        
        Args:
            action_class: The action class to add
            config: Configuration for the action
            
        Returns:
            The ID of the added action
        """
        try:
            # Create action instance
            action = action_class(config)
            action_id = action.action_id
            
            # Add to actions dictionary
            self.actions[action_id] = action
            
            self.logger.info(f"Added response action: {action_id}")
            return action_id
            
        except Exception as e:
            self.logger.error(f"Failed to add action {action_class.__name__}: {e}")
            raise
    
    def add_rule(
        self,
        rule_id: str,
        name: str,
        conditions: List[Dict[str, Any]],
        actions: List[Dict[str, Any]],
        enabled: bool = True
    ) -> str:
        """
        Add a response rule to the engine.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            conditions: List of conditions that must be met
            actions: List of actions to execute
            enabled: Whether the rule is enabled
            
        Returns:
            The ID of the added rule
        """
        rule = ResponseRule(rule_id, name, conditions, actions, enabled)
        self.rules[rule_id] = rule
        self.logger.info(f"Added response rule: {rule_id}")
        return rule_id
    
    def process_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process an alert through all response rules.
        
        Args:
            alert: The alert to process
            
        Returns:
            List of action results
        """
        results = []
        
        # Skip if not an alert
        if alert.get('event', {}).get('kind') != 'alert':
            self.logger.debug("Skipping non-alert event")
            return results
        
        # Check each rule
        for rule in self.rules.values():
            if rule.matches(alert):
                self.logger.info(f"Rule '{rule.name}' matched alert")
                
                # Queue the actions for this rule
                for action_config in rule.actions:
                    action_id = action_config.get('action')
                    action_params = action_config.get('params', {})
                    
                    if action_id in self.actions:
                        self.queue_action(
                            action_id=action_id,
                            alert=alert,
                            params=action_params
                        )
                        results.append({
                            'rule': rule.rule_id,
                            'action': action_id,
                            'status': 'queued'
                        })
                    else:
                        self.logger.warning(f"Unknown action: {action_id}")
                        results.append({
                            'rule': rule.rule_id,
                            'action': action_id,
                            'status': 'unknown_action'
                        })
        
        return results
    
    def queue_action(
        self, 
        action_id: str, 
        alert: Dict[str, Any],
        params: Dict[str, Any] = None
    ) -> None:
        """
        Queue an action for execution.
        
        Args:
            action_id: ID of the action to execute
            alert: The alert that triggered the action
            params: Additional parameters for the action
        """
        if action_id not in self.actions:
            self.logger.warning(f"Cannot queue unknown action: {action_id}")
            return
        
        with self.queue_lock:
            self.action_queue.append({
                'action_id': action_id,
                'alert': alert,
                'params': params or {},
                'queued_at': datetime.utcnow()
            })
    
    def _process_actions(self) -> None:
        """Background thread that processes queued actions."""
        while not self.stop_event.is_set():
            # Get the next action from the queue
            action_item = None
            with self.queue_lock:
                if self.action_queue:
                    action_item = self.action_queue.pop(0)
            
            if action_item:
                self._execute_action(action_item)
            else:
                # No actions in queue, sleep briefly
                time.sleep(0.1)
    
    def _execute_action(self, action_item: Dict[str, Any]) -> None:
        """Execute a single action."""
        action_id = action_item['action_id']
        alert = action_item['alert']
        params = action_item['params']
        
        if action_id not in self.actions:
            self.logger.error(f"Cannot execute unknown action: {action_id}")
            return
        
        action = self.actions[action_id]
        
        try:
            # Merge action params with any provided params
            action_params = {**action.config.get('params', {}), **params}
            
            # Execute the action
            self.logger.info(f"Executing action: {action_id}")
            result = action.execute(alert, **action_params)
            
            # Log the result
            if result.get('success'):
                self.logger.info(f"Action {action_id} completed successfully")
            else:
                self.logger.warning(
                    f"Action {action_id} failed: {result.get('message', 'Unknown error')}"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing action {action_id}: {e}", exc_info=True)
            return {
                'success': False,
                'message': f"Error executing action: {str(e)}"
            }
    
    def stop(self) -> None:
        """Stop the response engine."""
        self.stop_event.set()
        self.processor_thread.join(timeout=5)
        self.logger.info("Response engine stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status information about the response engine.
        
        Returns:
            Dictionary with status information
        """
        return {
            'status': 'running' if not self.stop_event.is_set() else 'stopped',
            'actions': {
                action_id: {
                    'name': action.name,
                    'enabled': action.enabled,
                    'type': action.__class__.__name__
                }
                for action_id, action in self.actions.items()
            },
            'rules': {
                rule_id: {
                    'name': rule.name,
                    'enabled': rule.enabled,
                    'condition_count': len(rule.conditions),
                    'action_count': len(rule.actions)
                }
                for rule_id, rule in self.rules.items()
            },
            'queue_size': len(self.action_queue)
        }
