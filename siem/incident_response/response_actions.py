"""
Automated Response Actions for Incident Response.

This module handles automated response actions that can be triggered by incidents.
"""
import logging
import subprocess
import shlex
from typing import Dict, Any, List, Optional, Callable, Tuple
from enum import Enum
import json
import time
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

class ActionType(Enum):
    """Types of automated response actions."""
    COMMAND = "command"
    SCRIPT = "script"
    WEBHOOK = "webhook"
    THROTTLE = "throttle"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    NOTIFICATION = "notification"
    CUSTOM = "custom"

class ActionStatus(Enum):
    """Status of an action execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class ActionContext:
    """Context for action execution."""
    
    def __init__(self, incident: Dict[str, Any], action_config: Dict[str, Any]):
        """Initialize the action context."""
        self.incident = incident
        self.action_config = action_config
        self.variables = self._extract_variables()
        
    def _extract_variables(self) -> Dict[str, Any]:
        """Extract variables from incident and action config."""
        vars = {
            'incident': self.incident,
            'action': self.action_config,
            'timestamp': datetime.utcnow().isoformat(),
            'action_id': hashlib.md5(json.dumps(self.action_config).encode()).hexdigest()
        }
        
        # Add common incident fields as top-level variables
        for field in ['id', 'title', 'severity', 'status', 'created_at']:
            if field in self.incident:
                vars[f'incident_{field}'] = self.incident[field]
        
        return vars
    
    def render_template(self, template: str) -> str:
        """Render a template string with context variables."""
        try:
            # Simple template rendering with string formatting
            return template.format(**self.variables)
        except KeyError as e:
            logger.warning(f"Missing variable in template: {e}")
            return template

class ResponseAction:
    """Base class for response actions."""
    
    def __init__(self, action_config: Dict[str, Any]):
        """Initialize the response action."""
        self.config = action_config
        self.type = ActionType(action_config.get('type', 'custom'))
        self.name = action_config.get('name', f"unnamed_{self.type.value}")
        self.enabled = action_config.get('enabled', True)
        self.timeout = action_config.get('timeout', 30)  # seconds
        self.conditions = action_config.get('conditions', [])
        self.parameters = action_config.get('parameters', {})
        
    def execute(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the action with the given incident context."""
        if not self.enabled:
            return self._create_result(ActionStatus.SKIPPED, "Action is disabled")
        
        context = ActionContext(incident, self.config)
        
        # Check conditions
        if not self._check_conditions(context):
            return self._create_result(ActionStatus.SKIPPED, "Conditions not met")
        
        try:
            # Execute the action
            start_time = time.time()
            result = self._execute(context)
            duration = time.time() - start_time
            
            # Add execution metrics
            result.update({
                'execution_time': duration,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing action {self.name}: {e}", exc_info=True)
            return self._create_result(ActionStatus.FAILED, str(e))
    
    def _check_conditions(self, context: ActionContext) -> bool:
        """Check if all conditions for this action are met."""
        if not self.conditions:
            return True
            
        # Simple condition checking - can be extended with more complex logic
        for condition in self.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict[str, Any], context: ActionContext) -> bool:
        """Evaluate a single condition."""
        # Simple condition evaluation - can be extended
        field = condition.get('field')
        operator = condition.get('operator', 'eq')
        value = condition.get('value')
        
        # Get the actual value from the incident
        actual = self._get_nested_value(context.incident, field)
        
        # Apply operator
        if operator == 'eq':
            return actual == value
        elif operator == 'ne':
            return actual != value
        elif operator == 'gt':
            return actual > value
        elif operator == 'lt':
            return actual < value
        elif operator == 'contains':
            return value in str(actual)
        elif operator == 'in':
            return actual in value
        elif operator == 'regex':
            import re
            return bool(re.search(value, str(actual)))
        
        return False
    
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
    
    def _execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the action (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement _execute")
    
    def _create_result(self, status: ActionStatus, message: str = "", **kwargs) -> Dict[str, Any]:
        """Create a result dictionary."""
        return {
            'action_name': self.name,
            'action_type': self.type.value,
            'status': status.value,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            **kwargs
        }

class CommandAction(ResponseAction):
    """Execute a shell command as a response action."""
    
    def _execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute a shell command."""
        command = self.parameters.get('command')
        if not command:
            return self._create_result(ActionStatus.FAILED, "No command specified")
        
        try:
            # Render the command template with incident data
            rendered_cmd = context.render_template(command)
            
            # Execute the command
            result = subprocess.run(
                shlex.split(rendered_cmd),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return self._create_result(
                ActionStatus.COMPLETED if result.returncode == 0 else ActionStatus.FAILED,
                f"Command executed with return code {result.returncode}",
                return_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr
            )
            
        except subprocess.TimeoutExpired:
            return self._create_result(
                ActionStatus.FAILED,
                f"Command timed out after {self.timeout} seconds"
            )
        except Exception as e:
            return self._create_result(
                ActionStatus.FAILED,
                f"Command execution failed: {str(e)}"
            )

class WebhookAction(ResponseAction):
    """Send an HTTP request to a webhook as a response action."""
    
    def _execute(self, context: ActionContext) -> Dict[str, Any]:
        """Send an HTTP request to a webhook."""
        import requests
        
        url = self.parameters.get('url')
        if not url:
            return self._create_result(ActionStatus.FAILED, "No URL specified")
        
        method = self.parameters.get('method', 'POST').upper()
        headers = self.parameters.get('headers', {})
        payload = self.parameters.get('payload', {})
        
        try:
            # Render templates in headers and payload
            rendered_headers = {
                k: context.render_template(v) for k, v in headers.items()
            }
            
            # Convert payload to string if it's a dict
            if isinstance(payload, dict):
                rendered_payload = json.dumps({
                    k: context.render_template(v) if isinstance(v, str) else v 
                    for k, v in payload.items()
                })
            else:
                rendered_payload = context.render_template(str(payload))
            
            # Send the request
            response = requests.request(
                method=method,
                url=url,
                headers=rendered_headers,
                data=rendered_payload,
                timeout=self.timeout
            )
            
            return self._create_result(
                ActionStatus.COMPLETED if response.ok else ActionStatus.FAILED,
                f"Webhook request completed with status {response.status_code}",
                status_code=response.status_code,
                response_text=response.text,
                response_headers=dict(response.headers)
            )
            
        except Exception as e:
            return self._create_result(
                ActionStatus.FAILED,
                f"Webhook request failed: {str(e)}"
            )

class BlockIPAction(ResponseAction):
    """Block an IP address using the system firewall."""
    
    def _execute(self, context: ActionContext) -> Dict[str, Any]:
        """Block an IP address."""
        ip_address = self.parameters.get('ip_address')
        if not ip_address:
            # Try to extract IP from incident
            ip_address = self._get_nested_value(context.incident, 'source.ip')
            
        if not ip_address:
            return self._create_result(ActionStatus.FAILED, "No IP address specified")
        
        # This is a simplified example - in a real implementation, you would
        # use the appropriate firewall commands for your system
        try:
            # Example for Linux with iptables
            command = f"iptables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                return self._create_result(
                    ActionStatus.COMPLETED,
                    f"Successfully blocked IP {ip_address}",
                    ip_address=ip_address
                )
            else:
                return self._create_result(
                    ActionStatus.FAILED,
                    f"Failed to block IP {ip_address}: {result.stderr}",
                    ip_address=ip_address,
                    stderr=result.stderr
                )
                
        except Exception as e:
            return self._create_result(
                ActionStatus.FAILED,
                f"Error blocking IP {ip_address}: {str(e)}",
                ip_address=ip_address
            )

class NotificationAction(ResponseAction):
    """Send a notification as a response action."""
    
    def _execute(self, context: ActionContext) -> Dict[str, Any]:
        """Send a notification."""
        message = self.parameters.get('message', 'Security incident detected')
        recipients = self.parameters.get('recipients', [])
        channel = self.parameters.get('channel', 'email')
        
        if not recipients:
            return self._create_result(ActionStatus.FAILED, "No recipients specified")
        
        try:
            # Render the message template with incident data
            rendered_message = context.render_template(message)
            
            # In a real implementation, you would send the notification here
            # This is just a placeholder
            logger.info(f"Sending {channel} notification to {', '.join(recipients)}: {rendered_message}")
            
            return self._create_result(
                ActionStatus.COMPLETED,
                f"Notification sent to {len(recipients)} recipient(s)",
                channel=channel,
                recipients=recipients,
                message=rendered_message
            )
            
        except Exception as e:
            return self._create_result(
                ActionStatus.FAILED,
                f"Failed to send notification: {str(e)}"
            )

class ResponseActionFactory:
    """Factory for creating response actions."""
    
    _action_types = {
        ActionType.COMMAND: CommandAction,
        ActionType.WEBHOOK: WebhookAction,
        ActionType.BLOCK: BlockIPAction,
        ActionType.NOTIFICATION: NotificationAction,
        # Add more action types here
    }
    
    @classmethod
    def create_action(cls, action_config: Dict[str, Any]) -> ResponseAction:
        """Create a response action from a configuration dictionary."""
        action_type = ActionType(action_config.get('type', 'custom'))
        action_class = cls._action_types.get(action_type, ResponseAction)
        
        return action_class(action_config)
    
    @classmethod
    def register_action_type(cls, action_type: ActionType, action_class: type) -> None:
        """Register a custom action type."""
        cls._action_types[action_type] = action_class

def execute_response_plan(
    incident: Dict[str, Any], 
    response_plan: Dict[str, Any],
    action_results_callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> List[Dict[str, Any]]:
    """Execute a response plan for an incident.
    
    Args:
        incident: The incident to respond to
        response_plan: The response plan configuration
        action_results_callback: Optional callback function to receive action results
        
    Returns:
        List of action results
    """
    if not response_plan.get('enabled', True):
        logger.info(f"Response plan '{response_plan.get('name', 'unknown')}' is disabled")
        return []
    
    action_configs = response_plan.get('actions', [])
    results = []
    
    for action_config in action_configs:
        try:
            action = ResponseActionFactory.create_action(action_config)
            result = action.execute(incident)
            results.append(result)
            
            # Notify callback if provided
            if action_results_callback:
                action_results_callback(result)
                
            logger.info(
                f"Executed action '{action.name}' with status {result['status']}: "
                f"{result.get('message', 'No message')}"
            )
            
        except Exception as e:
            error_result = {
                'action_name': action_config.get('name', 'unknown'),
                'action_type': action_config.get('type', 'unknown'),
                'status': ActionStatus.FAILED.value,
                'message': f"Error executing action: {str(e)}",
                'timestamp': datetime.utcnow().isoformat()
            }
            results.append(error_result)
            
            if action_results_callback:
                action_results_callback(error_result)
            
            logger.error(f"Error executing response action: {e}", exc_info=True)
    
    return results
