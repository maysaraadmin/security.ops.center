"""
Response Engine for NDR.
Handles alerts and executes response actions.
"""
import logging
from typing import Dict, List, Callable, Optional
import subprocess
import socket
import time
from datetime import datetime

class ResponseAction:
    """Represents a response action that can be taken when an alert is triggered."""
    
    def __init__(self, 
                 action_id: str,
                 name: str,
                 description: str,
                 execute: Callable[[Dict], bool],
                 severity_threshold: str = "medium"):
        """
        Initialize a response action.
        
        Args:
            action_id: Unique identifier for the action
            name: Human-readable name
            description: Description of what the action does
            execute: Function that executes the action, takes alert dict, returns success
            severity_threshold: Minimum severity required to trigger this action
        """
        self.id = action_id
        self.name = name
        self.description = description
        self.execute = execute
        self.severity_threshold = severity_threshold.lower()
        self.enabled = True


class ResponseEngine:
    """Handles alerts and executes appropriate response actions."""
    
    # Severity levels in order of importance
    SEVERITY_LEVELS = {
        'info': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    
    def __init__(self):
        """Initialize the response engine with default actions."""
        self.actions: Dict[str, ResponseAction] = {}
        self.logger = logging.getLogger(__name__)
        self._setup_default_actions()
    
    def add_action(self, action: ResponseAction):
        """Add a response action to the engine."""
        self.actions[action.id] = action
    
    def remove_action(self, action_id: str) -> bool:
        """Remove a response action."""
        if action_id in self.actions:
            del self.actions[action_id]
            return True
        return False
    
    def handle_alert(self, alert: Dict):
        """
        Process an alert and execute appropriate response actions.
        
        Args:
            alert: Alert dictionary containing at least 'severity' key
        """
        if not alert:
            return
            
        alert_severity = alert.get('severity', 'info').lower()
        
        for action in self.actions.values():
            if not action.enabled:
                continue
                
            # Check if alert severity meets the action's threshold
            if (self.SEVERITY_LEVELS.get(alert_severity, 0) >= 
                self.SEVERITY_LEVELS.get(action.severity_threshold, 0)):
                
                self.logger.info(f"Executing response action: {action.name}")
                try:
                    success = action.execute(alert)
                    if success:
                        self.logger.info(f"Successfully executed action: {action.name}")
                    else:
                        self.logger.warning(f"Action {action.name} reported failure")
                except Exception as e:
                    self.logger.error(f"Error executing action {action.name}: {e}")
    
    def _setup_default_actions(self):
        """Initialize the response engine with default actions."""
        # Log alert action (always enabled)
        self.add_action(ResponseAction(
            action_id="log-alert",
            name="Log Alert",
            description="Log all alerts to the system log",
            severity_threshold="info",
            execute=self._log_alert
        ))
        
        # Block IP action (for high severity alerts)
        self.add_action(ResponseAction(
            action_id="block-ip",
            name="Block Source IP",
            description="Block the source IP address in the local firewall",
            severity_threshold="high",
            execute=self._block_ip
        ))
        
        # Notify admin action (for medium+ severity)
        self.add_action(ResponseAction(
            action_id="notify-admin",
            name="Notify Administrator",
            description="Send a notification to the system administrator",
            severity_threshold="medium",
            execute=self._notify_admin
        ))
    
    # Default action implementations
    def _log_alert(self, alert: Dict) -> bool:
        """Log the alert to the system log."""
        try:
            self.logger.warning(
                f"ALERT [{alert.get('severity', 'unknown').upper()}] {alert.get('name')}: "
                f"{alert.get('description')} (Rule: {alert.get('rule_id', 'unknown')})"
            )
            return True
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}")
            return False
    
    def _block_ip(self, alert: Dict) -> bool:
        """Block the source IP in the local firewall."""
        src_ip = alert.get('source_ip')
        if not src_ip:
            return False
            
        try:
            # This is a simplified example - in a real implementation, you would:
            # 1. Check if the IP is already blocked
            # 2. Add the IP to the appropriate firewall rules
            # 3. Optionally schedule an unblock after a timeout
            
            # Example for Windows (using netsh)
            # subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
            #                f"name=\"Block {src_ip}\"", "dir=in", "action=block",
            #                f"remoteip={src_ip}"], check=True)
            
            self.logger.info(f"Blocked IP address: {src_ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {src_ip}: {e}")
            return False
    
    def _notify_admin(self, alert: Dict) -> bool:
        """Send a notification to the system administrator."""
        try:
            # In a real implementation, this might send an email, SMS, or other notification
            # This is a simplified example that just logs the notification
            self.logger.info(
                f"ADMIN NOTIFICATION: {alert.get('severity', 'UNKNOWN').upper()} - "
                f"{alert.get('name')}: {alert.get('description')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send admin notification: {e}")
            return False
