"""
Policy Management for HIPS

Enables administrators to define and enforce security policies including:
- Application whitelisting/blacklisting
- Script execution control
- User-based access control
- Least-privilege enforcement
"""

import os
import sys
import json
import logging
import hashlib
import platform
import threading
from typing import Dict, List, Set, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import time
import re

# Platform-specific imports
try:
    import win32security
    import win32api
    import win32con
    import ntsecuritycon
    import pywintypes
    WINDOWS = True
except ImportError:
    WINDOWS = False

logger = logging.getLogger(__name__)

class PolicyType(Enum):
    """Types of security policies."""
    APPLICATION_WHITELIST = "application_whitelist"
    APPLICATION_BLACKLIST = "application_blacklist"
    SCRIPT_EXECUTION = "script_execution"
    USER_ACCESS = "user_access"
    PRIVILEGE_MANAGEMENT = "privilege_management"
    NETWORK_ACCESS = "network_access"
    FILE_ACCESS = "file_access"
    REGISTRY_ACCESS = "registry_access"

class Action(Enum):
    """Actions that can be taken when a policy is matched."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    QUARANTINE = "quarantine"
    PROMPT = "prompt"

class MatchType(Enum):
    """How policy rules should be matched."""
    EXACT = "exact"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    CONTAINS = "contains"
    REGEX = "regex"
    HASH = "hash"
    CERTIFICATE = "certificate"
    PUBLISHER = "publisher"
    PATH = "path"

@dataclass
class PolicyRule:
    """A single policy rule definition."""
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    action: Action = Action.DENY
    match_type: MatchType = MatchType.EXACT
    target: str = ""
    conditions: Dict[str, Any] = field(default_factory=dict)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)
    priority: int = 100
    
    def matches(self, subject: Dict[str, Any]) -> bool:
        """Check if this rule matches the given subject."""
        if not self.enabled:
            return False
            
        # Check if any exception matches
        for exception in self.exceptions:
            if self._matches_condition(exception, subject):
                return False
        
        # Check if the rule matches
        return self._matches_condition(
            {"type": self.match_type, "value": self.target},
            subject
        )
    
    def _matches_condition(self, condition: Dict[str, Any], subject: Dict[str, Any]) -> bool:
        """Check if a condition matches the subject."""
        if not condition or 'type' not in condition or 'value' not in condition:
            return False
            
        value = condition['value']
        match_type = condition.get('type')
        
        # Handle different match types
        if match_type == MatchType.EXACT.value:
            return any(v == value for v in subject.values() if v is not None)
            
        elif match_type == MatchType.PREFIX.value:
            return any(str(v).startswith(value) for v in subject.values() if v is not None)
            
        elif match_type == MatchType.SUFFIX.value:
            return any(str(v).endswith(value) for v in subject.values() if v is not None)
            
        elif match_type == MatchType.CONTAINS.value:
            return any(value in str(v) for v in subject.values() if v is not None)
            
        elif match_type == MatchType.REGEX.value:
            try:
                pattern = re.compile(value, re.IGNORECASE)
                return any(
                    pattern.search(str(v)) is not None 
                    for v in subject.values() 
                    if v is not None
                )
            except re.error:
                logger.error(f"Invalid regex pattern: {value}")
                return False
                
        elif match_type == MatchType.HASH.value:
            file_path = subject.get('path', '')
            if not file_path or not os.path.isfile(file_path):
                return False
                
            file_hash = self._calculate_file_hash(file_path)
            return file_hash.lower() == value.lower()
            
        elif match_type == MatchType.PATH.value:
            path = subject.get('path', '')
            if not path:
                return False
                
            # Normalize paths for comparison
            path = os.path.abspath(os.path.normpath(path))
            value_path = os.path.abspath(os.path.normpath(value))
            
            return path == value_path
            
        return False
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate the hash of a file."""
        if algorithm.lower() == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm.lower() == 'md5':
            hasher = hashlib.md5()
        else:
            hasher = hashlib.sha1()
            
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""

@dataclass
class Policy:
    """A collection of policy rules for a specific policy type."""
    policy_type: PolicyType
    rules: List[PolicyRule] = field(default_factory=list)
    default_action: Action = Action.DENY
    
    def evaluate(self, subject: Dict[str, Any]) -> Action:
        """Evaluate the policy against a subject and return the resulting action."""
        # Sort rules by priority (lower number = higher priority)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority)
        
        # Check each rule in order
        for rule in sorted_rules:
            if rule.matches(subject):
                return rule.action
                
        # Return default action if no rules match
        return self.default_action
    
    def add_rule(self, rule: PolicyRule):
        """Add a rule to this policy."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

class PolicyManager:
    """Manages all security policies and enforces them."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the policy manager."""
        self.config = config or {}
        self.policies: Dict[PolicyType, Policy] = {}
        self.lock = threading.RLock()
        self.policy_file = self.config.get('policy_file')
        self.auto_save = self.config.get('auto_save', True)
        self._stop_event = threading.Event()
        
        # Initialize default policies
        self._initialize_default_policies()
        
        # Load policies from file if specified
        if self.policy_file and os.path.isfile(self.policy_file):
            self.load_policies()
    
    def _initialize_default_policies(self):
        """Initialize default security policies."""
        # Default application whitelist policy (deny all by default)
        self.policies[PolicyType.APPLICATION_WHITELIST] = Policy(
            policy_type=PolicyType.APPLICATION_WHITELIST,
            default_action=Action.DENY
        )
        
        # Default application blacklist policy (allow all by default)
        self.policies[PolicyType.APPLICATION_BLACKLIST] = Policy(
            policy_type=PolicyType.APPLICATION_BLACKLIST,
            default_action=Action.ALLOW
        )
        
        # Default script execution policy (restrictive by default)
        self.policies[PolicyType.SCRIPT_EXECUTION] = Policy(
            policy_type=PolicyType.SCRIPT_EXECUTION,
            default_action=Action.DENY
        )
        
        # Initialize other policy types with default allow
        for policy_type in PolicyType:
            if policy_type not in self.policies:
                self.policies[policy_type] = Policy(
                    policy_type=policy_type,
                    default_action=Action.ALLOW
                )
        
        # Add some default rules for security
        self._add_default_rules()
    
    def _add_default_rules(self):
        """Add default security rules."""
        # Block common script extensions by default
        for ext in ['.ps1', '.vbs', '.js', '.jse', '.vbe', '.wsf', '.wsh', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.ps1xml', '.ps2xml', '.psc1', '.psc2', '.mshxml', '.scf', '.lnk', '.inf', '.reg', '.bat', '.cmd', '.com']:
            self.add_rule(
                PolicyType.SCRIPT_EXECUTION,
                PolicyRule(
                    id=f"block_{ext[1:]}_scripts",
                    name=f"Block {ext} scripts",
                    description=f"Prevent execution of {ext} scripts",
                    action=Action.DENY,
                    match_type=MatchType.SUFFIX,
                    target=ext,
                    priority=10
                )
            )
        
        # Block common malware locations
        for path in ["%TEMP%\\*", "%APPDATA%\\*\\*.exe", "%USERPROFILE%\\*.exe"]:
            self.add_rule(
                PolicyType.APPLICATION_WHITELIST,
                PolicyRule(
                    id=f"block_temp_{hash(path)}",
                    name=f"Block executables in {path}",
                    description=f"Prevent execution from {path}",
                    action=Action.DENY,
                    match_type=MatchType.PATH,
                    target=os.path.expandvars(path),
                    priority=20
                )
            )
    
    def add_rule(self, policy_type: Union[PolicyType, str], rule: PolicyRule) -> bool:
        """Add a rule to the specified policy."""
        if isinstance(policy_type, str):
            try:
                policy_type = PolicyType(policy_type)
            except ValueError:
                logger.error(f"Invalid policy type: {policy_type}")
                return False
                
        with self.lock:
            if policy_type not in self.policies:
                self.policies[policy_type] = Policy(policy_type=policy_type)
                
            self.policies[policy_type].add_rule(rule)
            
            if self.auto_save and self.policy_file:
                self.save_policies()
                
            return True
    
    def remove_rule(self, policy_type: Union[PolicyType, str], rule_id: str) -> bool:
        """Remove a rule from the specified policy."""
        if isinstance(policy_type, str):
            try:
                policy_type = PolicyType(policy_type)
            except ValueError:
                logger.error(f"Invalid policy type: {policy_type}")
                return False
                
        with self.lock:
            if policy_type in self.policies:
                result = self.policies[policy_type].remove_rule(rule_id)
                if result and self.auto_save and self.policy_file:
                    self.save_policies()
                return result
            return False
    
    def evaluate(self, policy_type: Union[PolicyType, str], subject: Dict[str, Any]) -> Action:
        """Evaluate a subject against the specified policy type."""
        if isinstance(policy_type, str):
            try:
                policy_type = PolicyType(policy_type)
            except ValueError:
                logger.error(f"Invalid policy type: {policy_type}")
                return Action.DENY
                
        with self.lock:
            policy = self.policies.get(policy_type)
            if not policy:
                return Action.ALLOW  # Default allow if policy doesn't exist
                
            return policy.evaluate(subject)
    
    def check_application_execution(self, file_path: str, user_context: Optional[Dict] = None) -> bool:
        """Check if an application is allowed to execute."""
        if not file_path or not os.path.isfile(file_path):
            return False
            
        # Create subject for evaluation
        subject = {
            'path': os.path.abspath(file_path),
            'name': os.path.basename(file_path),
            'extension': os.path.splitext(file_path)[1].lower(),
            'user': user_context.get('username') if user_context else None,
            'group': user_context.get('group') if user_context else None
        }
        
        # Check blacklist first (deny if matched)
        blacklist_action = self.evaluate(PolicyType.APPLICATION_BLACKLIST, subject)
        if blacklist_action == Action.DENY:
            logger.warning(f"Application blocked by blacklist: {file_path}")
            return False
            
        # Then check whitelist (must be explicitly allowed)
        whitelist_action = self.evaluate(PolicyType.APPLICATION_WHITELIST, subject)
        if whitelist_action == Action.DENY:
            logger.warning(f"Application not in whitelist: {file_path}")
            return False
            
        return True
    
    def check_script_execution(self, script_path: str, user_context: Optional[Dict] = None) -> bool:
        """Check if a script is allowed to execute."""
        if not script_path or not os.path.isfile(script_path):
            return False
            
        # Create subject for evaluation
        subject = {
            'path': os.path.abspath(script_path),
            'name': os.path.basename(script_path),
            'extension': os.path.splitext(script_path)[1].lower(),
            'user': user_context.get('username') if user_context else None,
            'group': user_context.get('group') if user_context else None
        }
        
        # Check script execution policy
        action = self.evaluate(PolicyType.SCRIPT_EXECUTION, subject)
        
        if action == Action.DENY:
            logger.warning(f"Script execution blocked: {script_path}")
            return False
            
        return True
    
    def check_privilege(self, privilege: str, user_context: Optional[Dict] = None) -> bool:
        """Check if a user has the required privilege."""
        if not privilege:
            return False
            
        # Create subject for evaluation
        subject = {
            'privilege': privilege,
            'user': user_context.get('username') if user_context else None,
            'group': user_context.get('group') if user_context else None
        }
        
        # Check privilege policy
        action = self.evaluate(PolicyType.PRIVILEGE_MANAGEMENT, subject)
        
        if action == Action.DENY:
            logger.warning(f"Privilege denied: {privilege}")
            return False
            
        return True
    
    def save_policies(self, file_path: Optional[str] = None) -> bool:
        """Save all policies to a file."""
        file_path = file_path or self.policy_file
        if not file_path:
            return False
            
        try:
            with self.lock:
                # Prepare data for serialization
                data = {
                    'version': '1.0',
                    'policies': {}
                }
                
                for policy_type, policy in self.policies.items():
                    policy_data = {
                        'default_action': policy.default_action.value,
                        'rules': []
                    }
                    
                    for rule in policy.rules:
                        rule_data = asdict(rule)
                        rule_data['action'] = rule.action.value
                        rule_data['match_type'] = rule.match_type.value
                        policy_data['rules'].append(rule_data)
                    
                    data['policies'][policy_type.value] = policy_data
                
                # Save to file
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
                
                return True
                
        except Exception as e:
            logger.error(f"Error saving policies: {e}")
            return False
    
    def load_policies(self, file_path: Optional[str] = None) -> bool:
        """Load policies from a file."""
        file_path = file_path or self.policy_file
        if not file_path or not os.path.isfile(file_path):
            return False
            
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            with self.lock:
                # Clear existing policies
                self.policies.clear()
                
                # Load each policy
                for policy_type_str, policy_data in data.get('policies', {}).items():
                    try:
                        policy_type = PolicyType(policy_type_str)
                        policy = Policy(
                            policy_type=policy_type,
                            default_action=Action(policy_data.get('default_action', 'deny'))
                        )
                        
                        # Load rules
                        for rule_data in policy_data.get('rules', []):
                            try:
                                rule = PolicyRule(
                                    id=rule_data.get('id', ''),
                                    name=rule_data.get('name', ''),
                                    description=rule_data.get('description', ''),
                                    enabled=rule_data.get('enabled', True),
                                    action=Action(rule_data.get('action', 'deny')),
                                    match_type=MatchType(rule_data.get('match_type', 'exact')),
                                    target=rule_data.get('target', ''),
                                    conditions=rule_data.get('conditions', {}),
                                    exceptions=rule_data.get('exceptions', []),
                                    priority=rule_data.get('priority', 100)
                                )
                                policy.add_rule(rule)
                            except (KeyError, ValueError) as e:
                                logger.error(f"Error loading rule: {e}")
                                continue
                        
                        self.policies[policy_type] = policy
                        
                    except (KeyError, ValueError) as e:
                        logger.error(f"Error loading policy {policy_type_str}: {e}")
                        continue
                
                return True
                
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
            return False
    
    def stop(self):
        """Stop the policy manager and save policies if needed."""
        self._stop_event.set()
        if self.auto_save and self.policy_file:
            self.save_policies()

# Example usage
if __name__ == "__main__":
    import logging
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create a policy manager
    policy_manager = PolicyManager({
        'policy_file': 'security_policies.json',
        'auto_save': True
    })
    
    # Add some example rules
    policy_manager.add_rule(
        PolicyType.APPLICATION_WHITELIST,
        PolicyRule(
            id="allow_system32",
            name="Allow executables in System32",
            description="Allow execution of applications in the System32 directory",
            action=Action.ALLOW,
            match_type=MatchType.PATH,
            target=r"C:\\Windows\\System32\\*",
            priority=50
        )
    )
    
    policy_manager.add_rule(
        PolicyType.SCRIPT_EXECUTION,
        PolicyRule(
            id="block_powershell",
            name="Block PowerShell scripts",
            description="Prevent execution of PowerShell scripts",
            action=Action.DENY,
            match_type=MatchType.EXTENSION,
            target=".ps1",
            priority=10
        )
    )
    
    # Save policies to file
    policy_manager.save_policies()
    
    # Test application execution
    test_app = r"C:\Windows\System32\notepad.exe"
    if policy_manager.check_application_execution(test_app):
        print(f"Allowed to execute: {test_app}")
    else:
        print(f"Blocked from executing: {test_app}")
    
    # Test script execution
    test_script = r"C:\temp\test.ps1"
    if policy_manager.check_script_execution(test_script):
        print(f"Allowed to execute: {test_script}")
    else:
        print(f"Blocked from executing: {test_script}")
    
    # Clean up
    policy_manager.stop()
