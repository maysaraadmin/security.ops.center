"""
Automated Response & Remediation Engine for EDR.
Handles automated responses to security incidents including isolation, process termination, and file remediation.
"""
import logging
import platform
import subprocess
import shlex
import time
import json
import os
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from enum import Enum, auto
from dataclasses import dataclass, asdict
import ipaddress
import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..monitoring.base_monitor import BaseMonitor
from ..forensics.evidence import Evidence, EvidenceType
from ..alerting.alert_manager import Alert, AlertSeverity, AlertStatus

class ResponseAction(str, Enum):
    """Types of automated response actions."""
    ISOLATE_ENDPOINT = 'isolate_endpoint'
    KILL_PROCESS = 'kill_process'
    DELETE_FILE = 'delete_file'
    QUARANTINE_FILE = 'quarantine_file'
    BLOCK_IP = 'block_ip'
    BLOCK_DOMAIN = 'block_domain'
    DISABLE_USER = 'disable_user'
    REVERT_CHANGES = 'revert_changes'
    EXECUTE_COMMAND = 'execute_command'
    SEND_NOTIFICATION = 'send_notification'

@dataclass
class ResponseResult:
    """Result of a response action."""
    action: ResponseAction
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['action'] = self.action.value
        result['timestamp'] = self.timestamp
        return result

class ResponseEngine:
    """Automated response and remediation engine."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the response engine."""
        self.config = config
        self.logger = logging.getLogger('edr.response.engine')
        self.running = False
        self.action_queue = queue.Queue()
        self.worker_thread = None
        self.worker_pool = ThreadPoolExecutor(max_workers=5)
        self.is_windows = platform.system().lower() == 'windows'
        self.is_linux = platform.system().lower() == 'linux'
        self.is_macos = platform.system().lower() == 'darwin'
        
        # Load playbooks
        self.playbooks = self._load_playbooks()
        
        # Initialize response handlers
        self.handlers = {
            ResponseAction.ISOLATE_ENDPOINT: self._handle_isolate_endpoint,
            ResponseAction.KILL_PROCESS: self._handle_kill_process,
            ResponseAction.DELETE_FILE: self._handle_delete_file,
            ResponseAction.QUARANTINE_FILE: self._handle_quarantine_file,
            ResponseAction.BLOCK_IP: self._handle_block_ip,
            ResponseAction.BLOCK_DOMAIN: self._handle_block_domain,
            ResponseAction.DISABLE_USER: self._handle_disable_user,
            ResponseAction.REVERT_CHANGES: self._handle_revert_changes,
            ResponseAction.EXECUTE_COMMAND: self._handle_execute_command,
            ResponseAction.SEND_NOTIFICATION: self._handle_send_notification
        }
    
    def start(self) -> None:
        """Start the response engine."""
        if self.running:
            self.logger.warning("Response engine is already running")
            return
        
        self.running = True
        self.worker_thread = threading.Thread(
            target=self._process_actions,
            name="ResponseEngine-Worker",
            daemon=True
        )
        self.worker_thread.start()
        self.logger.info("Response engine started")
    
    def stop(self) -> None:
        """Stop the response engine."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=30)
        self.worker_pool.shutdown(wait=True)
        self.logger.info("Response engine stopped")
    
    def _process_actions(self) -> None:
        """Process actions from the queue."""
        while self.running:
            try:
                action = self.action_queue.get(timeout=1)
                if action is None:
                    break
                
                self.worker_pool.submit(self._execute_action, action)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing action: {e}", exc_info=True)
    
    def _execute_action(self, action: Dict[str, Any]) -> ResponseResult:
        """Execute a single response action."""
        try:
            action_type = ResponseAction(action['action'])
            handler = self.handlers.get(action_type)
            
            if not handler:
                return ResponseResult(
                    action=action_type,
                    success=False,
                    message=f"No handler for action type: {action_type}"
                )
            
            self.logger.info(f"Executing action: {action_type}")
            return handler(**action.get('parameters', {}))
            
        except Exception as e:
            self.logger.error(f"Failed to execute action {action}: {e}", exc_info=True)
            return ResponseResult(
                action=action_type,
                success=False,
                message=str(e)
            )
    
    def queue_action(self, action: Dict[str, Any]) -> None:
        """Queue a response action for execution."""
        self.action_queue.put(action)
    
    def execute_playbook(self, playbook_name: str, context: Dict[str, Any]) -> List[ResponseResult]:
        """Execute a response playbook."""
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            self.logger.error(f"Playbook not found: {playbook_name}")
            return [ResponseResult(
                action=ResponseAction(playbook_name),
                success=False,
                message=f"Playbook not found: {playbook_name}"
            )]
        
        self.logger.info(f"Executing playbook: {playbook_name}")
        results = []
        
        for action in playbook.get('actions', []):
            # Substitute variables in action parameters
            parameters = self._substitute_variables(action.get('parameters', {}), context)
            
            # Add additional context
            parameters['_playbook'] = playbook_name
            parameters['_context'] = context
            
            # Queue the action
            action_item = {
                'action': action['action'],
                'parameters': parameters
            }
            
            # Execute immediately and collect results
            result = self._execute_action(action_item)
            results.append(result)
            
            # Stop if action failed and playbook is set to stop on failure
            if not result.success and playbook.get('stop_on_failure', True):
                self.logger.warning(f"Playbook {playbook_name} stopped due to failed action: {action['action']}")
                break
        
        return results
    
    def _substitute_variables(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute variables in action parameters."""
        if not parameters:
            return {}
        
        result = {}
        for key, value in parameters.items():
            if isinstance(value, str):
                # Simple variable substitution: {{variable}}
                if value.startswith('{{') and value.endswith('}}'):
                    var_name = value[2:-2].strip()
                    result[key] = context.get(var_name, value)
                else:
                    result[key] = value
            elif isinstance(value, dict):
                result[key] = self._substitute_variables(value, context)
            elif isinstance(value, list):
                result[key] = [self._substitute_variables(
                    v, context) if isinstance(v, dict) else v for v in value]
            else:
                result[key] = value
        
        return result
    
    def _load_playbooks(self) -> Dict[str, Any]:
        """Load response playbooks from configuration."""
        playbooks_dir = self.config.get('playbooks_dir', os.path.join(
            os.path.dirname(__file__), 'playbooks'))
        playbooks = {}
        
        if not os.path.exists(playbooks_dir):
            self.logger.warning(f"Playbooks directory not found: {playbooks_dir}")
            return {}
        
        try:
            for filename in os.listdir(playbooks_dir):
                if not filename.endswith('.json'):
                    continue
                
                playbook_path = os.path.join(playbooks_dir, filename)
                with open(playbook_path, 'r') as f:
                    playbook = json.load(f)
                    playbook_name = os.path.splitext(filename)[0]
                    playbooks[playbook_name] = playbook
                    self.logger.info(f"Loaded playbook: {playbook_name}")
        
        except Exception as e:
            self.logger.error(f"Failed to load playbooks: {e}", exc_info=True)
        
        return playbooks
    
    # === Action Handlers ===
    
    def _handle_isolate_endpoint(self, **kwargs) -> ResponseResult:
        """Isolate the endpoint from the network."""
        try:
            if self.is_windows:
                # Windows: Disable network adapters
                self._run_command('netsh interface set interface "Ethernet" admin=disable')
                self._run_command('netsh interface set interface "Wi-Fi" admin=disable')
            elif self.is_linux:
                # Linux: Block all incoming/outgoing traffic
                self._run_command('iptables -P INPUT DROP')
                self._run_command('iptables -P OUTPUT DROP')
                self._run_command('iptables -P FORWARD DROP')
            elif self.is_macos:
                # macOS: Disable network interfaces
                self._run_command('networksetup -setairportpower airport off')
                self._run_command('networksetup -setnetworkserviceenabled "Ethernet" off')
            
            return ResponseResult(
                action=ResponseAction.ISOLATE_ENDPOINT,
                success=True,
                message="Endpoint isolated from network"
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.ISOLATE_ENDPOINT,
                success=False,
                message=f"Failed to isolate endpoint: {e}"
            )
    
    def _handle_kill_process(self, pid: int, force: bool = True, **kwargs) -> ResponseResult:
        """Kill a process."""
        try:
            if self.is_windows:
                cmd = f'taskkill /F /PID {pid}' if force else f'taskkill /PID {pid}'
            else:
                cmd = f'kill -9 {pid}' if force else f'kill {pid}'
            
            result = self._run_command(cmd)
            
            return ResponseResult(
                action=ResponseAction.KILL_PROCESS,
                success=result.returncode == 0,
                message=f"Process {pid} killed" if result.returncode == 0 else f"Failed to kill process {pid}",
                details={
                    'pid': pid,
                    'force': force,
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.KILL_PROCESS,
                success=False,
                message=f"Failed to kill process {pid}: {e}",
                details={'pid': pid, 'error': str(e)}
            )
    
    def _handle_delete_file(self, path: str, **kwargs) -> ResponseResult:
        """Delete a file."""
        try:
            if not os.path.exists(path):
                return ResponseResult(
                    action=ResponseAction.DELETE_FILE,
                    success=False,
                    message=f"File not found: {path}",
                    details={'path': path}
                )
            
            # Remove read-only attribute if on Windows
            if self.is_windows:
                self._run_command(f'attrib -r "{path}"')
            
            # Delete the file
            os.remove(path)
            
            return ResponseResult(
                action=ResponseAction.DELETE_FILE,
                success=True,
                message=f"File deleted: {path}",
                details={'path': path}
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.DELETE_FILE,
                success=False,
                message=f"Failed to delete file {path}: {e}",
                details={'path': path, 'error': str(e)}
            )
    
    def _handle_quarantine_file(self, path: str, quarantine_dir: str = None, **kwargs) -> ResponseResult:
        """Quarantine a file by moving it to a secure location."""
        try:
            if not os.path.exists(path):
                return ResponseResult(
                    action=ResponseAction.QUARANTINE_FILE,
                    success=False,
                    message=f"File not found: {path}",
                    details={'path': path}
                )
            
            # Set default quarantine directory if not specified
            if not quarantine_dir:
                quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
                os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate a unique filename for the quarantined file
            filename = os.path.basename(path)
            timestamp = int(time.time())
            quarantined_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}")
            
            # Move the file to quarantine
            shutil.move(path, quarantined_path)
            
            # Remove execute permissions (Unix-like systems)
            if not self.is_windows:
                os.chmod(quarantined_path, 0o600)
            
            return ResponseResult(
                action=ResponseAction.QUARANTINE_FILE,
                success=True,
                message=f"File quarantined: {path} -> {quarantined_path}",
                details={
                    'original_path': path,
                    'quarantined_path': quarantined_path,
                    'quarantine_dir': quarantine_dir,
                    'timestamp': timestamp
                }
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.QUARANTINE_FILE,
                success=False,
                message=f"Failed to quarantine file {path}: {e}",
                details={'path': path, 'error': str(e)}
            )
    
    def _handle_block_ip(self, ip: str, direction: str = 'both', **kwargs) -> ResponseResult:
        """Block an IP address."""
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            if self.is_windows:
                # Windows: Use Windows Firewall
                if direction in ['inbound', 'both']:
                    self._run_command(f'netsh advfirewall firewall add rule name="BLOCK_IP_IN_{ip}" dir=in action=block remoteip={ip}')
                if direction in ['outbound', 'both']:
                    self._run_command(f'netsh advfirewall firewall add rule name="BLOCK_IP_OUT_{ip}" dir=out action=block remoteip={ip}')
            else:
                # Linux/macOS: Use iptables/ipfw/pf
                if direction in ['inbound', 'both']:
                    self._run_command(f'iptables -A INPUT -s {ip} -j DROP')
                if direction in ['outbound', 'both']:
                    self._run_command(f'iptables -A OUTPUT -d {ip} -j DROP')
            
            return ResponseResult(
                action=ResponseAction.BLOCK_IP,
                success=True,
                message=f"IP blocked: {ip} ({direction})",
                details={'ip': ip, 'direction': direction}
            )
            
        except ValueError as e:
            return ResponseResult(
                action=ResponseAction.BLOCK_IP,
                success=False,
                message=f"Invalid IP address: {ip}",
                details={'ip': ip, 'error': str(e)}
            )
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.BLOCK_IP,
                success=False,
                message=f"Failed to block IP {ip}: {e}",
                details={'ip': ip, 'error': str(e)}
            )
    
    def _handle_block_domain(self, domain: str, **kwargs) -> ResponseResult:
        """Block a domain by adding it to the hosts file."""
        try:
            # Resolve domain to IP to block at network level as well
            try:
                ip = socket.gethostbyname(domain)
                self._handle_block_ip(ip, **kwargs)
            except socket.gaierror:
                pass  # Continue with hosts file blocking even if resolution fails
            
            # Add to hosts file
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts' if self.is_windows else '/etc/hosts'
            
            # Check if already blocked
            with open(hosts_path, 'r') as f:
                if domain in f.read():
                    return ResponseResult(
                        action=ResponseAction.BLOCK_DOMAIN,
                        success=True,
                        message=f"Domain already blocked: {domain}",
                        details={'domain': domain}
                    )
            
            # Add block entry
            with open(hosts_path, 'a') as f:
                f.write(f"\n127.0.0.1 {domain}\n::1 {domain}\n")
            
            return ResponseResult(
                action=ResponseAction.BLOCK_DOMAIN,
                success=True,
                message=f"Domain blocked: {domain}",
                details={'domain': domain}
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.BLOCK_DOMAIN,
                success=False,
                message=f"Failed to block domain {domain}: {e}",
                details={'domain': domain, 'error': str(e)}
            )
    
    def _handle_disable_user(self, username: str, **kwargs) -> ResponseResult:
        """Disable a user account."""
        try:
            if self.is_windows:
                self._run_command(f'net user {username} /active:no')
            else:
                self._run_command(f'usermod --expiredate 1 {username}')
                self._run_command(f'passwd -l {username}')
            
            return ResponseResult(
                action=ResponseAction.DISABLE_USER,
                success=True,
                message=f"User disabled: {username}",
                details={'username': username}
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.DISABLE_USER,
                success=False,
                message=f"Failed to disable user {username}: {e}",
                details={'username': username, 'error': str(e)}
            )
    
    def _handle_revert_changes(self, changes: List[Dict[str, Any]], **kwargs) -> ResponseResult:
        """Revert changes made by previous actions."""
        results = []
        
        for change in changes:
            action = change.get('action')
            params = change.get('parameters', {})
            
            if action == ResponseAction.BLOCK_IP:
                # Remove IP block rules
                ip = params.get('ip')
                if self.is_windows:
                    self._run_command(f'netsh advfirewall firewall delete rule name="BLOCK_IP_IN_{ip}"')
                    self._run_command(f'netsh advfirewall firewall delete rule name="BLOCK_IP_OUT_{ip}"')
                else:
                    self._run_command(f'iptables -D INPUT -s {ip} -j DROP')
                    self._run_command(f'iptables -D OUTPUT -d {ip} -j DROP')
                
                results.append(f"Reverted IP block: {ip}")
            
            elif action == ResponseAction.BLOCK_DOMAIN:
                # Remove domain from hosts file
                domain = params.get('domain')
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts' if self.is_windows else '/etc/hosts'
                
                with open(hosts_path, 'r') as f:
                    lines = f.readlines()
                
                with open(hosts_path, 'w') as f:
                    for line in lines:
                        if domain not in line:
                            f.write(line)
                
                results.append(f"Reverted domain block: {domain}")
            
            elif action == ResponseAction.QUARANTINE_FILE:
                # Restore file from quarantine
                original_path = params.get('original_path')
                quarantined_path = params.get('quarantined_path')
                
                if os.path.exists(quarantined_path):
                    shutil.move(quarantined_path, original_path)
                    results.append(f"Restored file from quarantine: {original_path}")
            
            # Add more revert actions as needed
        
        return ResponseResult(
            action=ResponseAction.REVERT_CHANGES,
            success=True,
            message=f"Reverted {len(results)} changes",
            details={'reverted_changes': results}
        )
    
    def _handle_execute_command(self, command: str, shell: bool = False, **kwargs) -> ResponseResult:
        """Execute a custom command."""
        try:
            result = self._run_command(command, shell=shell)
            
            return ResponseResult(
                action=ResponseAction.EXECUTE_COMMAND,
                success=result.returncode == 0,
                message=f"Command executed with return code {result.returncode}",
                details={
                    'command': command,
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.EXECUTE_COMMAND,
                success=False,
                message=f"Failed to execute command: {e}",
                details={'command': command, 'error': str(e)}
            )
    
    def _handle_send_notification(self, message: str, recipients: List[str], **kwargs) -> ResponseResult:
        """Send a notification to specified recipients."""
        try:
            # In a real implementation, this would integrate with email, Slack, etc.
            self.logger.info(f"Notification to {', '.join(recipients)}: {message}")
            
            return ResponseResult(
                action=ResponseAction.SEND_NOTIFICATION,
                success=True,
                message=f"Notification sent to {len(recipients)} recipients",
                details={
                    'message': message,
                    'recipients': recipients
                }
            )
            
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.SEND_NOTIFICATION,
                success=False,
                message=f"Failed to send notification: {e}",
                details={'error': str(e)}
            )
    
    def _run_command(self, command: str, shell: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command and return the result."""
        try:
            if not shell and not self.is_windows:
                command = shlex.split(command)
            
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                check=False
            )
            
            self.logger.debug(f"Command executed: {command}")
            self.logger.debug(f"Return code: {result.returncode}")
            self.logger.debug(f"Stdout: {result.stdout}")
            if result.stderr:
                self.logger.debug(f"Stderr: {result.stderr}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Command failed: {command} - {e}")
            raise

class ResponseOrchestrator:
    """Orchestrates automated responses based on alerts and policies."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the response orchestrator."""
        self.config = config
        self.engine = ResponseEngine(config)
        self.logger = logging.getLogger('edr.response.orchestrator')
        self.alert_history = []
        self.max_history = config.get('max_alert_history', 1000)
        
        # Start the response engine
        self.engine.start()
    
    def process_alert(self, alert: Alert) -> List[ResponseResult]:
        """Process an alert and determine appropriate response actions."""
        try:
            # Add alert to history
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_history:
                self.alert_history.pop(0)
            
            # Determine response actions based on alert
            response_actions = self._determine_response_actions(alert)
            
            # Execute response actions
            results = []
            for action in response_actions:
                result = self.engine._execute_action(action)
                results.append(result)
                
                # Update alert with response results
                if 'response_results' not in alert.metadata:
                    alert.metadata['response_results'] = []
                alert.metadata['response_results'].append(result.to_dict())
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing alert {alert.alert_id}: {e}", exc_info=True)
            return [ResponseResult(
                action=ResponseAction.SEND_NOTIFICATION,
                success=False,
                message=f"Error processing alert: {e}"
            )]
    
    def _determine_response_actions(self, alert: Alert) -> List[Dict[str, Any]]:
        """Determine appropriate response actions based on alert."""
        actions = []
        
        # High severity alerts get immediate isolation
        if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            # Check if this is a network-based threat
            if 'source_ip' in alert.metadata or 'dest_ip' in alert.metadata:
                actions.append({
                    'action': ResponseAction.BLOCK_IP,
                    'parameters': {
                        'ip': alert.metadata.get('source_ip') or alert.metadata.get('dest_ip'),
                        'direction': 'both'
                    }
                })
            
            # Check if this is a process-based threat
            if 'process_id' in alert.metadata:
                actions.append({
                    'action': ResponseAction.KILL_PROCESS,
                    'parameters': {
                        'pid': alert.metadata['process_id'],
                        'force': True
                    }
                })
            
            # Check if this is a file-based threat
            if 'file_path' in alert.metadata:
                actions.append({
                    'action': ResponseAction.QUARANTINE_FILE,
                    'parameters': {
                        'path': alert.metadata['file_path']
                    }
                })
            
            # If we're dealing with a critical threat, consider isolating the endpoint
            if alert.severity == AlertSeverity.CRITICAL:
                actions.append({
                    'action': ResponseAction.ISOLATE_ENDPOINT,
                    'parameters': {}
                })
        
        # Medium severity alerts might get less aggressive responses
        elif alert.severity == AlertSeverity.MEDIUM:
            if 'file_path' in alert.metadata:
                actions.append({
                    'action': ResponseAction.QUARANTINE_FILE,
                    'parameters': {
                        'path': alert.metadata['file_path']
                    }
                })
        
        # Always log the alert
        actions.append({
            'action': ResponseAction.SEND_NOTIFICATION,
            'parameters': {
                'message': f"Alert triggered: {alert.title} - {alert.description}",
                'recipients': self.config.get('notification_recipients', ['security-team@example.com'])
            }
        })
        
        return actions
    
    def execute_playbook(self, playbook_name: str, context: Dict[str, Any]) -> List[ResponseResult]:
        """Execute a response playbook."""
        return self.engine.execute_playbook(playbook_name, context)
    
    def stop(self) -> None:
        """Stop the response orchestrator."""
        self.engine.stop()

# Example playbook (would be in a separate JSON file)
EXAMPLE_PLAYBOOK = {
    "name": "respond_to_ransomware",
    "description": "Response actions for ransomware detection",
    "actions": [
        {
            "action": "isolate_endpoint",
            "parameters": {}
        },
        {
            "action": "kill_process",
            "parameters": {
                "pid": "{{process_id}}",
                "force": true
            }
        },
        {
            "action": "quarantine_file",
            "parameters": {
                "path": "{{file_path}}"
            }
        },
        {
            "action": "block_ip",
            "parameters": {
                "ip": "{{source_ip}}",
                "direction": "both"
            }
        },
        {
            "action": "send_notification",
            "parameters": {
                "message": "Ransomware detected and contained. Endpoint isolated and malicious process terminated.",
                "recipients": ["security-team@example.com", "it-support@example.com"]
            }
        }
    ],
    "stop_on_failure": true
}
