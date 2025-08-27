"""
Automated Response Engine for NIPS

This module provides automated response capabilities for the Network Intrusion Prevention System,
allowing for immediate action to be taken when threats are detected.
"""

import logging
import time
import threading
import ipaddress
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum, auto
import json
import subprocess
import socket
import re

logger = logging.getLogger('nips.response_engine')

class ResponseAction(Enum):
    """Types of automated response actions."""
    BLOCK_IP = auto()
    DROP_CONNECTION = auto()
    QUARANTINE_HOST = auto()
    ALERT_ONLY = auto()
    RATE_LIMIT = auto()
    LOG_EVENT = auto()
    EXECUTE_SCRIPT = auto()
    UPDATE_FIREWALL = auto()
    ISOLATE_NETWORK = auto()
    TERMINATE_PROCESS = auto()

class ResponseSeverity(Enum):
    """Severity levels for response actions."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class ResponseRule:
    """Defines a response rule with conditions and actions."""
    id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    severity: ResponseSeverity
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'actions': self.actions,
            'severity': self.severity.name,
            'enabled': self.enabled,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResponseRule':
        """Create a ResponseRule from a dictionary."""
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            conditions=data.get('conditions', []),
            actions=data.get('actions', []),
            severity=ResponseSeverity[data.get('severity', 'MEDIUM')],
            enabled=data.get('enabled', True),
            created_at=data.get('created_at', time.time()),
            updated_at=data.get('updated_at', time.time())
        )

class ResponseEngine:
    """Automated response engine for taking action on detected threats."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the response engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rules: Dict[str, ResponseRule] = {}
        self.lock = threading.Lock()
        self.action_handlers = {
            ResponseAction.BLOCK_IP: self._handle_block_ip,
            ResponseAction.DROP_CONNECTION: self._handle_drop_connection,
            ResponseAction.QUARANTINE_HOST: self._handle_quarantine_host,
            ResponseAction.ALERT_ONLY: self._handle_alert,
            ResponseAction.RATE_LIMIT: self._handle_rate_limit,
            ResponseAction.LOG_EVENT: self._handle_log_event,
            ResponseAction.EXECUTE_SCRIPT: self._handle_execute_script,
            ResponseAction.UPDATE_FIREWALL: self._handle_update_firewall,
            ResponseAction.ISOLATE_NETWORK: self._handle_isolate_network,
            ResponseAction.TERMINATE_PROCESS: self._handle_terminate_process,
        }
        
        # Track blocked IPs and their expiration times
        self.blocked_ips: Dict[str, float] = {}
        self.blocked_connections: Set[str] = set()
        self.quarantined_hosts: Dict[str, float] = {}
        
        # Load default rules if none exist
        if not self.rules:
            self._load_default_rules()
        
        # Start cleanup thread for expired blocks
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("Response Engine initialized")
    
    def _load_default_rules(self) -> None:
        """Load default response rules."""
        default_rules = [
            {
                'id': 'block_high_confidence_malware',
                'name': 'Block High Confidence Malware',
                'description': 'Block IPs associated with high confidence malware distribution',
                'conditions': [
                    {'field': 'threat_score', 'operator': '>=', 'value': 90},
                    {'field': 'threat_type', 'operator': '==', 'value': 'malware'}
                ],
                'actions': [
                    {'action': 'BLOCK_IP', 'target': 'source_ip', 'duration': 86400},
                    {'action': 'ALERT_ONLY', 'message': 'Blocked IP {source_ip} due to high confidence malware'}
                ],
                'severity': 'HIGH'
            },
            {
                'id': 'rate_limit_bruteforce',
                'name': 'Rate Limit Brute Force Attempts',
                'description': 'Rate limit IPs with multiple failed login attempts',
                'conditions': [
                    {'field': 'event_type', 'operator': '==', 'value': 'failed_login'},
                    {'field': 'event_count', 'operator': '>=', 'value': 5}
                ],
                'actions': [
                    {'action': 'RATE_LIMIT', 'target': 'source_ip', 'rate': '10/60s', 'duration': 3600},
                    {'action': 'LOG_EVENT', 'message': 'Rate limiting {source_ip} due to multiple failed logins'}
                ],
                'severity': 'MEDIUM'
            },
            {
                'id': 'quarantine_infected_host',
                'name': 'Quarantine Infected Host',
                'description': 'Quarantine hosts with active malware infections',
                'conditions': [
                    {'field': 'threat_type', 'operator': '==', 'value': 'malware'},
                    {'field': 'confidence', 'operator': '>=', 'value': 80}
                ],
                'actions': [
                    {'action': 'QUARANTINE_HOST', 'target': 'host_id', 'duration': 86400},
                    {'action': 'ALERT_ONLY', 'message': 'Quarantined host {host_id} due to malware infection'}
                ],
                'severity': 'CRITICAL'
            }
        ]
        
        for rule_data in default_rules:
            rule = ResponseRule.from_dict(rule_data)
            self.add_rule(rule)
    
    def add_rule(self, rule: ResponseRule) -> bool:
        """Add a new response rule.
        
        Args:
            rule: The response rule to add
            
        Returns:
            bool: True if the rule was added successfully
        """
        with self.lock:
            if rule.id in self.rules:
                logger.warning(f"Rule with ID {rule.id} already exists")
                return False
                
            self.rules[rule.id] = rule
            logger.info(f"Added response rule: {rule.name} (ID: {rule.id})")
            return True
    
    def update_rule(self, rule_id: str, rule_data: Dict[str, Any]) -> bool:
        """Update an existing response rule.
        
        Args:
            rule_id: ID of the rule to update
            rule_data: Updated rule data
            
        Returns:
            bool: True if the rule was updated successfully
        """
        with self.lock:
            if rule_id not in self.rules:
                logger.warning(f"Rule with ID {rule_id} not found")
                return False
                
            # Preserve the original ID and timestamps
            rule_data['id'] = rule_id
            if 'created_at' not in rule_data:
                rule_data['created_at'] = self.rules[rule_id].created_at
            rule_data['updated_at'] = time.time()
            
            self.rules[rule_id] = ResponseRule.from_dict(rule_data)
            logger.info(f"Updated response rule: {rule_id}")
            return True
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a response rule.
        
        Args:
            rule_id: ID of the rule to delete
            
        Returns:
            bool: True if the rule was deleted successfully
        """
        with self.lock:
            if rule_id not in self.rules:
                logger.warning(f"Rule with ID {rule_id} not found")
                return False
                
            del self.rules[rule_id]
            logger.info(f"Deleted response rule: {rule_id}")
            return True
    
    def get_rule(self, rule_id: str) -> Optional[ResponseRule]:
        """Get a response rule by ID.
        
        Args:
            rule_id: ID of the rule to retrieve
            
        Returns:
            Optional[ResponseRule]: The rule if found, None otherwise
        """
        with self.lock:
            return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[ResponseRule]:
        """Get all response rules.
        
        Returns:
            List[ResponseRule]: List of all response rules
        """
        with self.lock:
            return list(self.rules.values())
    
    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate an event against all response rules.
        
        Args:
            event: The event to evaluate
            
        Returns:
            List[Dict[str, Any]]: List of actions taken
        """
        triggered_actions = []
        
        with self.lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                    
                if self._evaluate_conditions(rule.conditions, event):
                    logger.info(f"Rule '{rule.name}' triggered for event: {event.get('event_id', 'unknown')}")
                    
                    # Execute all actions for this rule
                    for action in rule.actions:
                        try:
                            action_type = ResponseAction[action['action']]
                            handler = self.action_handlers.get(action_type)
                            if handler:
                                result = handler(action, event, rule)
                                triggered_actions.append({
                                    'rule_id': rule.id,
                                    'rule_name': rule.name,
                                    'action': action,
                                    'result': result,
                                    'timestamp': time.time()
                                })
                        except Exception as e:
                            logger.error(f"Error executing action {action}: {e}", exc_info=True)
        
        return triggered_actions
    
    def _evaluate_conditions(self, conditions: List[Dict[str, Any]], event: Dict[str, Any]) -> bool:
        """Evaluate if all conditions are met for an event.
        
        Args:
            conditions: List of conditions to evaluate
            event: The event data
            
        Returns:
            bool: True if all conditions are met, False otherwise
        """
        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')
            
            if field not in event:
                return False
                
            event_value = event[field]
            
            # Handle different operators
            if operator == '==':
                if event_value != value:
                    return False
            elif operator == '!=':
                if event_value == value:
                    return False
            elif operator == '>':
                if not (event_value > value):
                    return False
            elif operator == '>=':
                if not (event_value >= value):
                    return False
            elif operator == '<':
                if not (event_value < value):
                    return False
            elif operator == '<=':
                if not (event_value <= value):
                    return False
            elif operator == 'contains':
                if value not in event_value:
                    return False
            elif operator == 'not_contains':
                if value in event_value:
                    return False
            elif operator == 'in':
                if event_value not in value:
                    return False
            elif operator == 'not_in':
                if event_value in value:
                    return False
            elif operator == 'regex':
                if not re.search(value, str(event_value)):
                    return False
            else:
                logger.warning(f"Unsupported operator: {operator}")
                return False
        
        return True
    
    def _format_message(self, message: str, event: Dict[str, Any]) -> str:
        """Format a message with event data.
        
        Args:
            message: The message template
            event: The event data
            
        Returns:
            str: Formatted message
        """
        try:
            return message.format(**event)
        except KeyError as e:
            logger.warning(f"Missing key in message template: {e}")
            return message
    
    # Action Handlers
    def _handle_block_ip(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle BLOCK_IP action."""
        ip = event.get(action.get('target', 'source_ip'))
        duration = action.get('duration', 3600)  # Default 1 hour
        
        if not ip or not self._is_valid_ip(ip):
            return {'success': False, 'error': 'Invalid IP address'}
        
        with self.lock:
            self.blocked_ips[ip] = time.time() + duration
            
        logger.warning(f"Blocked IP {ip} for {duration} seconds (Rule: {rule.name})")
        return {'success': True, 'ip': ip, 'duration': duration}
    
    def _handle_drop_connection(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle DROP_CONNECTION action."""
        conn_id = f"{event.get('source_ip')}:{event.get('source_port')}-{event.get('dest_ip')}:{event.get('dest_port')}"
        
        with self.lock:
            self.blocked_connections.add(conn_id)
            
        logger.warning(f"Dropped connection {conn_id} (Rule: {rule.name})")
        return {'success': True, 'connection': conn_id}
    
    def _handle_quarantine_host(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle QUARANTINE_HOST action."""
        host_id = event.get(action.get('target', 'host_id'))
        duration = action.get('duration', 86400)  # Default 24 hours
        
        if not host_id:
            return {'success': False, 'error': 'No host ID provided'}
        
        with self.lock:
            self.quarantined_hosts[host_id] = time.time() + duration
            
        logger.warning(f"Quarantined host {host_id} for {duration} seconds (Rule: {rule.name})")
        return {'success': True, 'host_id': host_id, 'duration': duration}
    
    def _handle_alert(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle ALERT_ONLY action."""
        message = self._format_message(action.get('message', 'Alert triggered'), event)
        logger.warning(f"ALERT: {message} (Rule: {rule.name})")
        return {'success': True, 'message': message}
    
    def _handle_rate_limit(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle RATE_LIMIT action."""
        target = event.get(action.get('target', 'source_ip'))
        rate = action.get('rate', '10/60s')  # Default: 10 requests per 60 seconds
        duration = action.get('duration', 3600)  # Default 1 hour
        
        if not target:
            return {'success': False, 'error': 'No target specified for rate limiting'}
        
        # TODO: Implement actual rate limiting logic
        logger.warning(f"Rate limiting {target} at {rate} for {duration} seconds (Rule: {rule.name})")
        return {'success': True, 'target': target, 'rate': rate, 'duration': duration}
    
    def _handle_log_event(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle LOG_EVENT action."""
        message = self._format_message(action.get('message', 'Event logged'), event)
        log_level = action.get('level', 'info').lower()
        
        if log_level == 'debug':
            logger.debug(message)
        elif log_level == 'info':
            logger.info(message)
        elif log_level == 'warning':
            logger.warning(message)
        elif log_level == 'error':
            logger.error(message)
        elif log_level == 'critical':
            logger.critical(message)
        else:
            logger.info(message)
            
        return {'success': True, 'message': message, 'level': log_level}
    
    def _handle_execute_script(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle EXECUTE_SCRIPT action."""
        script = action.get('script')
        if not script:
            return {'success': False, 'error': 'No script provided'}
        
        try:
            # Format script with event data
            formatted_script = self._format_message(script, event)
            
            # Execute the script
            result = subprocess.run(
                formatted_script,
                shell=True,
                capture_output=True,
                text=True,
                timeout=action.get('timeout', 30)
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Script execution timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_update_firewall(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle UPDATE_FIREWALL action.
        
        Note: This is a platform-specific implementation and may need adjustment
        based on the target operating system.
        """
        # TODO: Implement firewall update logic for different platforms
        logger.warning(f"Firewall update requested (Rule: {rule.name})")
        return {'success': False, 'error': 'Firewall update not implemented'}
    
    def _handle_isolate_network(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle ISOLATE_NETWORK action."""
        # TODO: Implement network isolation logic
        logger.warning(f"Network isolation requested (Rule: {rule.name})")
        return {'success': False, 'error': 'Network isolation not implemented'}
    
    def _handle_terminate_process(self, action: Dict[str, Any], event: Dict[str, Any], rule: ResponseRule) -> Dict[str, Any]:
        """Handle TERMINATE_PROCESS action."""
        pid = event.get(action.get('target', 'process_id'))
        if not pid:
            return {'success': False, 'error': 'No process ID provided'}
        
        try:
            # Platform-specific process termination
            import os
            import signal
            os.kill(pid, signal.SIGTERM)
            return {'success': True, 'pid': pid}
            
        except ProcessLookupError:
            return {'success': False, 'error': f'Process {pid} not found'}
        except PermissionError:
            return {'success': False, 'error': f'Permission denied when terminating process {pid}'}
        except Exception as e:
            return {'success': False, 'error': f'Error terminating process {pid}: {str(e)}'}
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if the IP is blocked, False otherwise
        """
        if not self._is_valid_ip(ip):
            return False
            
        with self.lock:
            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    # Clean up expired block
                    del self.blocked_ips[ip]
        return False
    
    def is_host_quarantined(self, host_id: str) -> bool:
        """Check if a host is currently quarantined.
        
        Args:
            host_id: Host ID to check
            
        Returns:
            bool: True if the host is quarantined, False otherwise
        """
        with self.lock:
            if host_id in self.quarantined_hosts:
                if time.time() < self.quarantined_hosts[host_id]:
                    return True
                else:
                    # Clean up expired quarantine
                    del self.quarantined_hosts[host_id]
        return False
    
    def _cleanup_expired_blocks(self) -> None:
        """Background thread to clean up expired blocks and quarantines."""
        while self.running:
            try:
                current_time = time.time()
                
                with self.lock:
                    # Clean up expired IP blocks
                    expired_ips = [ip for ip, expiry in self.blocked_ips.items() 
                                 if expiry < current_time]
                    for ip in expired_ips:
                        del self.blocked_ips[ip]
                        logger.info(f"Expired block for IP: {ip}")
                    
                    # Clean up expired host quarantines
                    expired_hosts = [host for host, expiry in self.quarantined_hosts.items()
                                   if expiry < current_time]
                    for host in expired_hosts:
                        del self.quarantined_hosts[host]
                        logger.info(f"Expired quarantine for host: {host}")
                
                # Sleep for 1 minute between cleanups
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}", exc_info=True)
                time.sleep(30)  # Wait before retrying on error
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if a string is a valid IP address.
        
        Args:
            ip: IP address to validate
            
        Returns:
            bool: True if the IP is valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def stop(self) -> None:
        """Stop the response engine and clean up resources."""
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        self._save_rules()
    
    def _save_rules(self) -> None:
        """Save response rules to persistent storage."""
        try:
            rules_data = [rule.to_dict() for rule in self.rules.values()]
            # TODO: Implement actual persistence (e.g., to a file or database)
            logger.info(f"Saved {len(rules_data)} response rules")
        except Exception as e:
            logger.error(f"Error saving response rules: {e}", exc_info=True)
    
    def load_rules(self, rules_data: List[Dict[str, Any]]) -> None:
        """Load response rules from persistent storage.
        
        Args:
            rules_data: List of rule dictionaries
        """
        with self.lock:
            self.rules.clear()
            for rule_data in rules_data:
                try:
                    rule = ResponseRule.from_dict(rule_data)
                    self.rules[rule.id] = rule
                except Exception as e:
                    logger.error(f"Error loading rule {rule_data.get('id')}: {e}")
            
            logger.info(f"Loaded {len(self.rules)} response rules")
