"""
Policy Manager Module

This module provides policy management capabilities for the HIPS system,
handling security policies, access controls, and policy enforcement.
"""

import os
import re
import json
import logging
import threading
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger('hips.policy_manager')

@dataclass
class PolicyRule:
    """Represents a security policy rule."""
    id: str
    name: str
    description: str
    enabled: bool = True
    action: str = 'alert'  # alert, block, quarantine, terminate
    severity: str = 'medium'  # info, low, medium, high, critical
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

class PolicyManager:
    """Manages security policies and access controls."""
    
    def __init__(self, config: Dict):
        """Initialize the policy manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.policies_dir = Path(config.get('policies_dir', 'policies'))
        self.default_policies = config.get('default_policies', {})
        
        self.rules: Dict[str, PolicyRule] = {}
        self.rule_lock = threading.RLock()
        
        # Initialize default policies
        self._init_default_policies()
        
        # Load policies from disk if available
        self._load_policies()
        
        logger.info(f"Policy manager initialized with {len(self.rules)} rules")
    
    def _init_default_policies(self):
        """Initialize default security policies."""
        default_rules = [
            # Process execution policies
            PolicyRule(
                id="exec_block_suspicious_paths",
                name="Block execution from suspicious paths",
                description="Prevent execution from temporary and suspicious locations",
                action="block",
                severity="high",
                conditions={
                    "type": "process_execution",
                    "paths": [
                        "/tmp/*",
                        "/var/tmp/*",
                        "/dev/shm/*",
                        "C:\\Windows\\Temp\\*",
                        "%TEMP%\\*"
                    ]
                }
            ),
            
            # Network connection policies
            PolicyRule(
                id="net_block_malicious_ips",
                name="Block connections to known malicious IPs",
                description="Automatically block connections to known malicious IP addresses",
                action="block",
                severity="high"
            ),
            
            # File access policies
            PolicyRule(
                id="file_protect_sensitive",
                name="Protect sensitive files",
                description="Prevent unauthorized access to sensitive system files",
                action="alert",
                severity="high",
                conditions={
                    "type": "file_access",
                    "paths": [
                        "/etc/passwd",
                        "/etc/shadow",
                        "C:\\Windows\\System32\\config\\*"
                    ],
                    "access_types": ["write", "delete", "rename"]
                }
            ),
            
            # Privilege escalation policies
            PolicyRule(
                id="priv_escalation_detection",
                name="Detect privilege escalation attempts",
                description="Alert on potential privilege escalation attempts",
                action="alert",
                severity="critical"
            )
        ]
        
        # Add default rules if not overridden by config
        for rule in default_rules:
            if rule.id not in self.rules:
                self.rules[rule.id] = rule
    
    def _load_policies(self):
        """Load policies from disk."""
        if not self.policies_dir.exists():
            try:
                self.policies_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created policies directory: {self.policies_dir}")
            except Exception as e:
                logger.error(f"Failed to create policies directory: {e}")
                return
        
        # Load policy files
        for policy_file in self.policies_dir.glob("*.json"):
            try:
                with open(policy_file, 'r') as f:
                    policy_data = json.load(f)
                    
                if not isinstance(policy_data, list):
                    policy_data = [policy_data]
                    
                for rule_data in policy_data:
                    try:
                        rule = PolicyRule(**rule_data)
                        self.rules[rule.id] = rule
                    except Exception as e:
                        logger.error(f"Invalid policy in {policy_file}: {e}")
                        
                logger.info(f"Loaded {len(policy_data)} policies from {policy_file}")
                
            except Exception as e:
                logger.error(f"Failed to load policy file {policy_file}: {e}")
    
    def save_policies(self):
        """Save all policies to disk."""
        if not self.policies_dir.exists():
            try:
                self.policies_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create policies directory: {e}")
                return False
        
        # Group rules by policy file
        policy_groups = {}
        for rule in self.rules.values():
            group = rule.metadata.get('group', 'default')
            if group not in policy_groups:
                policy_groups[group] = []
            policy_groups[group].append(rule)
        
        # Save each policy group to a separate file
        saved = 0
        for group, rules in policy_groups.items():
            policy_file = self.policies_dir / f"{group}.json"
            try:
                with open(policy_file, 'w') as f:
                    json.dump(
                        [self._rule_to_dict(rule) for rule in rules],
                        f,
                        indent=2,
                        default=str
                    )
                saved += 1
            except Exception as e:
                logger.error(f"Failed to save policy file {policy_file}: {e}")
        
        logger.info(f"Saved {saved} policy files to {self.policies_dir}")
        return saved > 0
    
    def _rule_to_dict(self, rule: PolicyRule) -> Dict:
        """Convert a PolicyRule to a dictionary."""
        return {
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'enabled': rule.enabled,
            'action': rule.action,
            'severity': rule.severity,
            'conditions': rule.conditions,
            'metadata': rule.metadata
        }
    
    def add_rule(self, rule: PolicyRule) -> bool:
        """Add or update a policy rule."""
        with self.rule_lock:
            self.rules[rule.id] = rule
            return True
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a policy rule by ID."""
        with self.rule_lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                return True
            return False
    
    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        """Get a policy rule by ID."""
        return self.rules.get(rule_id)
    
    def get_rules(self, filter_enabled: bool = None) -> List[PolicyRule]:
        """Get all policy rules, optionally filtered by enabled status."""
        with self.rule_lock:
            if filter_enabled is not None:
                return [r for r in self.rules.values() if r.enabled == filter_enabled]
            return list(self.rules.values())
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a policy rule."""
        with self.rule_lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = enabled
                return True
            return False
    
    def check_process_execution(self, process_info: Dict) -> Tuple[bool, Optional[PolicyRule]]:
        """Check if a process execution is allowed by policy."""n        with self.rule_lock:
            for rule in self.rules.values():
                if not rule.enabled or rule.conditions.get('type') != 'process_execution':
                    continue
                
                # Check path patterns
                if 'paths' in rule.conditions:
                    if self._matches_patterns(process_info.get('path', ''), rule.conditions['paths']):
                        return False, rule
                
                # Check command line patterns
                if 'cmdline_patterns' in rule.conditions:
                    cmdline = process_info.get('cmdline', '')
                    if any(re.search(p, cmdline, re.IGNORECASE) for p in rule.conditions['cmdline_patterns']):
                        return False, rule
            
            return True, None
    
    def check_file_access(self, file_path: str, access_type: str, process_info: Dict) -> Tuple[bool, Optional[PolicyRule]]:
        """Check if file access is allowed by policy."""
        with self.rule_lock:
            for rule in self.rules.values():
                if not rule.enabled or rule.conditions.get('type') != 'file_access':
                    continue
                
                # Check if this rule applies to the file path
                if 'paths' in rule.conditions:
                    if not self._matches_patterns(file_path, rule.conditions['paths']):
                        continue
                
                # Check access type
                if 'access_types' in rule.conditions:
                    if access_type not in rule.conditions['access_types']:
                        continue
                
                # Check process restrictions if any
                if 'process_restrictions' in rule.conditions:
                    if not self._check_process_restrictions(process_info, rule.conditions['process_restrictions']):
                        continue
                
                return False, rule
            
            return True, None
    
    def check_network_connection(self, conn_info: Dict) -> Tuple[bool, Optional[PolicyRule]]:
        """Check if a network connection is allowed by policy."""
        with self.rule_lock:
            for rule in self.rules.values():
                if not rule.enabled or rule.conditions.get('type') != 'network_connection':
                    continue
                
                # Check remote address
                if 'remote_addresses' in rule.conditions:
                    if not self._matches_patterns(conn_info.get('remote_address', ''), rule.conditions['remote_addresses']):
                        continue
                
                # Check port
                if 'remote_ports' in rule.conditions:
                    if conn_info.get('remote_port') not in rule.conditions['remote_ports']:
                        continue
                
                # Check protocol
                if 'protocols' in rule.conditions:
                    if conn_info.get('protocol') not in rule.conditions['protocols']:
                        continue
                
                # Check process restrictions if any
                if 'process_restrictions' in rule.conditions:
                    if not self._check_process_restrictions(conn_info.get('process', {}), rule.conditions['process_restrictions']):
                        continue
                
                return False, rule
            
            return True, None
    
    def _matches_patterns(self, value: str, patterns: List[str]) -> bool:
        """Check if a value matches any of the given patterns."""
        import fnmatch
        
        for pattern in patterns:
            # Expand environment variables in the pattern
            expanded_pattern = os.path.expandvars(pattern)
            
            # Simple glob matching
            if fnmatch.fnmatch(value, expanded_pattern):
                return True
            
            # Try case-insensitive matching on Windows
            if os.name == 'nt' and fnmatch.fnmatch(value.lower(), expanded_pattern.lower()):
                return True
        
        return False
    
    def _check_process_restrictions(self, process_info: Dict, restrictions: Dict) -> bool:
        """Check if a process matches the given restrictions."""
        # Check process path
        if 'paths' in restrictions:
            if not self._matches_patterns(process_info.get('path', ''), restrictions['paths']):
                return False
        
        # Check process name
        if 'names' in restrictions:
            if not self._matches_patterns(process_info.get('name', ''), restrictions['names']):
                return False
        
        # Check user/owner
        if 'users' in restrictions:
            if process_info.get('username', '') not in restrictions['users']:
                return False
        
        # Check command line
        if 'cmdline_patterns' in restrictions:
            cmdline = process_info.get('cmdline', '')
            if not any(re.search(p, cmdline, re.IGNORECASE) for p in restrictions['cmdline_patterns']):
                return False
        
        return True
    
    def get_effective_policy(self, policy_type: str = None) -> Dict:
        """Get the effective policy settings for a given type."""
        effective = {
            'enabled_rules': [],
            'disabled_rules': []
        }
        
        with self.rule_lock:
            for rule in self.rules.values():
                if policy_type and rule.conditions.get('type') != policy_type:
                    continue
                    
                rule_data = self._rule_to_dict(rule)
                if rule.enabled:
                    effective['enabled_rules'].append(rule_data)
                else:
                    effective['disabled_rules'].append(rule_data)
        
        return effective
    
    def import_policy(self, policy_data: Dict) -> bool:
        """Import a policy from a dictionary."""
        try:
            if not isinstance(policy_data, list):
                policy_data = [policy_data]
                
            imported = 0
            for rule_data in policy_data:
                try:
                    rule = PolicyRule(**rule_data)
                    self.rules[rule.id] = rule
                    imported += 1
                except Exception as e:
                    logger.error(f"Invalid policy data: {e}")
                    
            logger.info(f"Imported {imported} policy rules")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import policy: {e}")
            return False
    
    def export_policy(self, rule_ids: List[str] = None) -> List[Dict]:
        """Export policies to a list of dictionaries."""
        with self.rule_lock:
            if rule_ids:
                return [self._rule_to_dict(self.rules[rid]) for rid in rule_ids if rid in self.rules]
            return [self._rule_to_dict(rule) for rule in self.rules.values()]
    
    def reset_to_defaults(self) -> bool:
        """Reset all policies to default values."""
        with self.rule_lock:
            self.rules.clear()
            self._init_default_policies()
            
        # Save the default policies
        return self.save_policies()
