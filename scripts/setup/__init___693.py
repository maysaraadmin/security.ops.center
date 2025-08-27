"""
EDR Response Module

This module handles automated response actions when threats are detected.
"""

import logging
import subprocess
import platform
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger('edr.response')

class ActionType(Enum):
    """Types of response actions."""
    NOTIFY = auto()
    QUARANTINE = auto()
    KILL_PROCESS = auto()
    BLOCK_IP = auto()
    ISOLATE_ENDPOINT = auto()
    COLLECT_FORENSICS = auto()
    EXECUTE_SCRIPT = auto()

@dataclass
class ResponseAction:
    """Base class for response actions."""
    action_type: ActionType
    name: str
    description: str
    enabled: bool = True
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the response action."""
        raise NotImplementedError("Subclasses must implement execute()")

@dataclass
class KillProcessAction(ResponseAction):
    """Action to terminate a process."""
    
    def __post_init__(self):
        self.action_type = ActionType.KILL_PROCESS
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Kill the process associated with the alert."""
        event = alert.get("event", {})
        pid = event.get("pid")
        
        if not pid:
            return {"success": False, "error": "No process ID in alert"}
        
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True)
            else:
                subprocess.run(["kill", "-9", str(pid)], check=True)
                
            return {"success": True, "message": f"Killed process {pid}"}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": f"Failed to kill process {pid}: {e}"}

@dataclass
class BlockIPAction(ResponseAction):
    """Action to block an IP address."""
    
    def __post_init__(self):
        self.action_type = ActionType.BLOCK_IP
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Block the IP address associated with the alert."""
        event = alert.get("event", {})
        ip_address = event.get("remote_ip")
        
        if not ip_address:
            return {"success": False, "error": "No IP address in alert"}
        
        try:
            # This is a simplified example. In a real implementation, you would:
            # 1. Add the IP to the firewall rules
            # 2. Update any network security groups
            # 3. Potentially update router/firewall configurations
            
            if platform.system() == "Windows":
                # Windows firewall rule example
                rule_name = f"Block_EDR_{ip_address}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    f"remoteip={ip_address}",
                    "action=block"
                ], check=True)
            else:
                # Linux iptables example
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            
            return {"success": True, "message": f"Blocked IP {ip_address}"}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": f"Failed to block IP {ip_address}: {e}"}

@dataclass
class IsolateEndpointAction(ResponseAction):
    """Action to isolate an endpoint from the network."""
    
    def __post_init__(self):
        self.action_type = ActionType.ISOLATE_ENDPOINT
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate the endpoint from the network."""
        try:
            if platform.system() == "Windows":
                # Disable all network adapters
                subprocess.run(["netsh", "interface", "set", "interface", "name=\"*\"", "admin=disabled"], 
                             shell=True, check=True)
            else:
                # Bring down all network interfaces (Linux)
                subprocess.run(["ifdown", "-a"], check=True)
            
            return {"success": True, "message": "Endpoint isolated from network"}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": f"Failed to isolate endpoint: {e}"}

class ResponseEngine:
    """Manages and executes response actions."""
    
    def __init__(self):
        self.actions: Dict[str, ResponseAction] = {}
        self._register_default_actions()
    
    def _register_default_actions(self) -> None:
        """Register default response actions."""
        self.add_action(KillProcessAction(
            name="kill_malicious_process",
            description="Terminate processes associated with malicious activity"
        ))
        
        self.add_action(BlockIPAction(
            name="block_malicious_ip",
            description="Block IP addresses associated with malicious activity"
        ))
        
        self.add_action(IsolateEndpointAction(
            name="isolate_endpoint",
            description="Isolate the endpoint from the network"
        ))
    
    def add_action(self, action: ResponseAction) -> None:
        """Add a response action."""
        self.actions[action.name] = action
    
    def remove_action(self, name: str) -> bool:
        """Remove a response action by name."""
        if name in self.actions:
            del self.actions[name]
            return True
        return False
    
    def execute_action(self, action_name: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a response action by name."""
        action = self.actions.get(action_name)
        if not action:
            return {"success": False, "error": f"Unknown action: {action_name}"}
        
        if not action.enabled:
            return {"success": False, "error": f"Action {action_name} is disabled"}
        
        logger.info(f"Executing response action: {action_name}")
        try:
            result = action.execute(alert)
            logger.info(f"Action {action_name} completed: {result}")
            return result
        except Exception as e:
            error_msg = f"Error executing action {action_name}: {e}"
            logger.error(error_msg, exc_info=True)
            return {"success": False, "error": error_msg}
    
    def get_available_actions(self) -> List[Dict[str, Any]]:
        """Get a list of available response actions."""
        return [
            {
                "name": action.name,
                "type": action.action_type.name,
                "description": action.description,
                "enabled": action.enabled
            }
            for action in self.actions.values()
        ]
