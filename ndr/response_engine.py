"""
Automated Response Engine for NDR

Handles automated responses to security events including:
- Blocking malicious IPs
- Quarantining devices
- Triggering SIEM/SOAR integrations
- Executing playbook-driven responses
"""
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from pathlib import Path
import yaml

from .models.alert import NetworkAlert, AlertSeverity
from .models.flow import NetworkFlow, Protocol

logger = logging.getLogger('ndr.response')

class ResponseActionType(Enum):
    """Types of automated response actions."""
    BLOCK_IP = "block_ip"
    QUARANTINE_DEVICE = "quarantine_device"
    EXECUTE_COMMAND = "execute_command"
    WEBHOOK = "webhook"
    UPDATE_FIREWALL = "update_firewall"
    NOTIFY = "notify"

@dataclass
class ResponseAction:
    """A response action to be executed."""
    action_type: ResponseActionType
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None
    priority: int = 0
    enabled: bool = True

class ResponseEngine:
    """Core response engine for handling automated threat responses."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the response engine."""
        self.config = config or {}
        self.playbooks: Dict[str, Dict] = {}
        self.active = False
        
    async def start(self):
        """Start the response engine."""
        if self.active:
            return
            
        self.active = True
        await self._load_playbooks()
        logger.info("Response engine started")
    
    async def stop(self):
        """Stop the response engine."""
        self.active = False
        logger.info("Response engine stopped")
    
    async def process_alert(self, alert: NetworkAlert):
        """Process an alert and execute appropriate responses."""
        if not self.active:
            logger.warning("Response engine is not active")
            return
            
        # Find matching playbooks
        matched_playbooks = [p for p in self.playbooks.values() 
                           if self._playbook_matches_alert(p, alert)]
        
        if not matched_playbooks:
            logger.debug(f"No playbooks matched alert: {alert.id}")
            return
            
        logger.info(f"Processing alert {alert.id} with {len(matched_playbooks)} playbooks")
        
        # Execute actions from all matching playbooks
        for playbook in matched_playbooks:
            await self._execute_playbook(playbook, alert)
    
    def _playbook_matches_alert(self, playbook: Dict, alert: NetworkAlert) -> bool:
        """Check if a playbook matches the given alert."""
        if not playbook.get('enabled', True):
            return False
            
        # Check severity conditions
        min_severity = playbook.get('min_severity')
        if min_severity and alert.severity.value < AlertSeverity[min_severity].value:
            return False
            
        # Check alert type
        alert_types = playbook.get('alert_types', [])
        if alert_types and alert.alert_type not in alert_types:
            return False
            
        # Check tags
        required_tags = set(playbook.get('required_tags', []))
        if required_tags and not required_tags.issubset(alert.tags):
            return False
            
        return True
    
    async def _execute_playbook(self, playbook: Dict, alert: NetworkAlert):
        """Execute all actions in a playbook."""
        logger.info(f"Executing playbook: {playbook['name']}")
        
        # Sort actions by priority (highest first)
        actions = sorted(playbook.get('actions', []), 
                        key=lambda x: x.get('priority', 0), 
                        reverse=True)
        
        for action_data in actions:
            try:
                action = ResponseAction(
                    action_type=ResponseActionType(action_data['type']),
                    target=action_data['target'],
                    parameters=action_data.get('parameters', {}),
                    condition=action_data.get('condition'),
                    priority=action_data.get('priority', 0),
                    enabled=action_data.get('enabled', True)
                )
                
                await self._execute_action(action, alert)
                
            except Exception as e:
                logger.error(f"Error executing action: {e}", exc_info=True)
    
    async def _execute_action(self, action: ResponseAction, alert: NetworkAlert):
        """Execute a single response action."""
        if not action.enabled:
            return
            
        # Check condition if specified
        if action.condition and not self._evaluate_condition(action.condition, alert):
            return
            
        logger.info(f"Executing {action.action_type.value} on {action.target}")
        
        # Execute the appropriate action handler
        handler_name = f"_handle_{action.action_type.value}"
        handler = getattr(self, handler_name, None)
        
        if not handler:
            logger.warning(f"No handler for action type: {action.action_type}")
            return
            
        try:
            await handler(action.target, action.parameters, alert)
        except Exception as e:
            logger.error(f"Error in {handler_name}: {e}", exc_info=True)
    
    def _evaluate_condition(self, condition: str, alert: NetworkAlert) -> bool:
        """Evaluate a condition string against an alert."""
        try:
            # Simple condition evaluation - in production, use a proper expression evaluator
            return eval(condition, {
                'alert': alert,
                'has_tag': lambda tags: any(tag in alert.tags for tag in tags)
            })
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False
    
    # Action handlers
    async def _handle_block_ip(self, target: str, parameters: Dict, alert: NetworkAlert):
        """Block an IP address."""
        # Implementation depends on your network infrastructure
        # This is a simplified example
        logger.info(f"Blocking IP {target}")
        
        # Example: Call firewall API or execute command
        # await self._execute_command(f"iptables -A INPUT -s {target} -j DROP")
        
    async def _handle_quarantine_device(self, target: str, parameters: Dict, alert: NetworkAlert):
        """Quarantine a device."""
        logger.info(f"Quarantining device {target}")
        # Implementation would interact with network infrastructure
        
    async def _handle_webhook(self, target: str, parameters: Dict, alert: NetworkAlert):
        """Send a webhook notification."""
        import aiohttp
        
        url = parameters.get('url', target)
        method = parameters.get('method', 'POST').upper()
        headers = parameters.get('headers', {'Content-Type': 'application/json'})
        payload = parameters.get('payload', {
            'alert_id': alert.id,
            'title': alert.title,
            'severity': alert.severity.value,
            'timestamp': alert.timestamp.isoformat(),
            'source_ip': alert.source_ip
        })
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    method=method,
                    url=url,
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status >= 400:
                        logger.error(f"Webhook failed with status {response.status}")
            except Exception as e:
                logger.error(f"Webhook error: {e}")
    
    async def _load_playbooks(self):
        """Load response playbooks from the configured directory."""
        playbooks_dir = Path(self.config.get('playbooks_dir', 'config/response_playbooks'))
        playbooks_dir.mkdir(parents=True, exist_ok=True)
        
        for playbook_file in playbooks_dir.glob('*.yaml'):
            try:
                with open(playbook_file, 'r') as f:
                    playbook = yaml.safe_load(f)
                    playbook_id = playbook.get('id') or playbook_file.stem
                    self.playbooks[playbook_id] = playbook
                    logger.info(f"Loaded playbook: {playbook.get('name', playbook_id)}")
            except Exception as e:
                logger.error(f"Error loading playbook {playbook_file}: {e}")
