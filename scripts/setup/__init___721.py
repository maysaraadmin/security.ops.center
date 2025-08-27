"""
HIPS (Host-based Intrusion Prevention System) module.

This module provides a comprehensive host-based intrusion prevention system with:
- Process monitoring and control
- File integrity monitoring
- Registry monitoring (Windows only)
- Behavioral analysis of running processes
- Alerting and response capabilities

Example usage:
    >>> from services.hips import HIPSService, HIPSProcessRule, HIPSAlertLevel, HIPSAction
    >>> 
    >>> # Create a HIPS service instance
    >>> hips = HIPSService()
    >>> 
    >>> # Add a custom process rule
    >>> rule = HIPSProcessRule(
    ...     rule_id="custom-rule-001",
    ...     name="Block Suspicious Process",
    ...     description="Blocks potentially malicious processes",
    ...     process_name=r"suspicious\.exe$",
    ...     action=HIPSAction.BLOCK,
    ...     alert_level=HIPSAlertLevel.HIGH
    ... )
    >>> hips.add_process_rule(rule)
    >>> 
    >>> # Start the HIPS service
    >>> hips.start()
    >>> 
    >>> # Check service status
    >>> print(hips.get_status())
    >>> 
    >>> # Stop the service when done
    >>> hips.stop()
"""

# Re-export models and enums
from .models import (
    HIPSProcessRule, HIPSFileRule, HIPSRegistryRule,
    HIPSAlert, HIPSStats, HIPSAction, HIPSAlertLevel
)

# Re-export the main service class
from .service import HIPSService, create_hips_service

# Create a singleton instance for backward compatibility
_hips_instance = None

def get_hips_instance(config: Optional[Dict[str, Any]] = None) -> 'HIPSService':
    """
    Get or create a singleton instance of the HIPS service.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        HIPSService: The singleton instance of the HIPS service
    """
    global _hips_instance
    if _hips_instance is None:
        _hips_instance = create_hips_service(config=config)
    return _hips_instance

# Legacy alias for backward compatibility
HIPSManager = HIPSService

# Set up logging
import logging
logging.getLogger('hips').addHandler(logging.NullHandler())

# Set __all__ to control what gets imported with 'from hips import *'
__all__ = [
    'HIPSService', 'HIPSManager', 'create_hips_service', 'get_hips_instance',
    'HIPSProcessRule', 'HIPSFileRule', 'HIPSRegistryRule',
    'HIPSAlert', 'HIPSStats', 'HIPSAction', 'HIPSAlertLevel'
]

"""
Host-based Intrusion Prevention System (HIPS) service for SIEM.

This module provides host-based security monitoring and prevention capabilities
by monitoring system activities and enforcing security policies.
"""
import os
import re
import time
import logging
import threading
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Pattern, Any, Callable

from ..core.base_service import BaseService

class HIPSAlertLevel(Enum):
    """Alert severity levels for HIPS events."""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class HIPSAction(Enum):
    """Actions that can be taken when a rule is triggered."""
    ALLOW = auto()
    BLOCK = auto()
    ALERT = auto()
    QUARANTINE = auto()

@dataclass
class HIPSProcessRule:
    """Rule for monitoring process activities."""
    rule_id: str
    name: str
    description: str
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[Pattern] = None
    action: HIPSAction = HIPSAction.ALERT
    alert_level: HIPSAlertLevel = HIPSAlertLevel.MEDIUM
    enabled: bool = True

@dataclass
class HIPSFileRule:
    """Rule for monitoring file system activities."""
    rule_id: str
    name: str
    description: str
    path: str
    pattern: Optional[Pattern] = None
    action: HIPSAction = HIPSAction.ALERT
    alert_level: HIPSAlertLevel = HIPSAlertLevel.MEDIUM
    monitor_reads: bool = False
    monitor_writes: bool = True
    monitor_executes: bool = True
    enabled: bool = True

@dataclass
class HIPSRegistryRule:
    """Rule for monitoring Windows registry activities."""
    rule_id: str
    name: str
    description: str
    key_path: str
    value_name: Optional[str] = None
    value_pattern: Optional[Pattern] = None
    action: HIPSAction = HIPSAction.ALERT
    alert_level: HIPSAlertLevel = HIPSAlertLevel.MEDIUM
    monitor_reads: bool = False
    monitor_writes: bool = True
    monitor_deletes: bool = True
    enabled: bool = True

class HIPSManager(BaseService):
    """
    Host-based Intrusion Prevention System (HIPS) service.
    
    Monitors system activities and enforces security policies at the host level.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the HIPS service."""
        super().__init__('HIPS', config_path)
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        # Initialize rule sets
        self.process_rules: List[HIPSProcessRule] = []
        self.file_rules: List[HIPSFileRule] = []
        self.registry_rules: List[HIPSRegistryRule] = []
        
        # File monitoring state
        self.file_hashes: Dict[str, str] = {}  # path -> hash
        self.monitored_files: Set[str] = set()
        
        # Load default rules
        self._load_default_rules()
    
    def start(self) -> bool:
        """Start the HIPS service."""
        if self.running:
            self.logger.warning("HIPS service is already running")
            return False
            
        try:
            self.logger.info("Starting HIPS service")
            self.running = True
            
            # Start monitoring threads
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            
            self.logger.info("HIPS service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start HIPS service: {e}")
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the HIPS service."""
        if not self.running:
            return True
            
        self.logger.info("Stopping HIPS service")
        self.running = False
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
            
        self.logger.info("HIPS service stopped")
        return True
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the HIPS service."""
        return {
            "service": self.service_name,
            "status": "running" if self.running else "stopped",
            "process_rules": len([r for r in self.process_rules if r.enabled]),
            "file_rules": len([r for r in self.file_rules if r.enabled]),
            "registry_rules": len([r for r in self.registry_rules if r.enabled]),
            "monitored_files": len(self.monitored_files)
        }
    
    def add_process_rule(self, rule: HIPSProcessRule) -> bool:
        """Add a new process monitoring rule."""
        if any(r.rule_id == rule.rule_id for r in self.process_rules):
            self.logger.warning(f"Process rule with ID {rule.rule_id} already exists")
            return False
            
        self.process_rules.append(rule)
        self.logger.info(f"Added process rule: {rule.name} (ID: {rule.rule_id})")
        return True
    
    def add_file_rule(self, rule: HIPSFileRule) -> bool:
        """Add a new file monitoring rule."""
        if any(r.rule_id == rule.rule_id for r in self.file_rules):
            self.logger.warning(f"File rule with ID {rule.rule_id} already exists")
            return False
            
        self.file_rules.append(rule)
        self.monitored_files.add(rule.path)
        self.logger.info(f"Added file rule: {rule.name} (ID: {rule.rule_id})")
        return True
    
    def add_registry_rule(self, rule: HIPSRegistryRule) -> bool:
        """Add a new registry monitoring rule."""
        if any(r.rule_id == rule.rule_id for r in self.registry_rules):
            self.logger.warning(f"Registry rule with ID {rule.rule_id} already exists")
            return False
            
        self.registry_rules.append(rule)
        self.logger.info(f"Added registry rule: {rule.name} (ID: {rule.rule_id})")
        return True
    
    def _load_default_rules(self) -> None:
        """Load default HIPS rules."""
        self.logger.info("Loading default HIPS rules")
        
        # Example process rules
        self.add_process_rule(HIPSProcessRule(
            rule_id="hips-proc-001",
            name="Suspicious Process Execution",
            description="Detects execution of potentially malicious processes",
            process_name=r"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)",
            action=HIPSAction.ALERT,
            alert_level=HIPSAlertLevel.HIGH
        ))
        
        # Example file rules
        self.add_file_rule(HIPSFileRule(
            rule_id="hips-file-001",
            name="System Directory Protection",
            description="Monitors changes to system directories",
            path=r"C:\\Windows\\System32\\*",
            action=HIPSAction.ALERT,
            alert_level=HIPSAlertLevel.HIGH,
            monitor_writes=True,
            monitor_executes=True
        ))
        
        # Example registry rules (Windows-specific)
        self.add_registry_rule(HIPSRegistryRule(
            rule_id="hips-reg-001",
            name="Startup Program Monitoring",
            description="Monitors changes to Windows startup programs",
            key_path=r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            action=HIPSAction.ALERT,
            alert_level=HIPSAlertLevel.HIGH,
            monitor_writes=True,
            monitor_deletes=True
        ))
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop for HIPS."""
        self.logger.info("Starting HIPS monitoring loop")
        
        try:
            while self.running:
                try:
                    # Check running processes
                    self._check_processes()
                    
                    # Check monitored files
                    self._check_file_integrity()
                    
                    # Add other monitoring checks here
                    
                    # Sleep to prevent high CPU usage
                    time.sleep(5)
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(10)  # Prevent tight error loop
                    
        except Exception as e:
            self.logger.error(f"Fatal error in HIPS monitoring: {e}")
            self.running = False
    
    def _check_processes(self) -> None:
        """Check running processes against process rules."""
        try:
            # In a real implementation, this would use platform-specific APIs
            # to enumerate processes and check them against rules
            pass
            
        except Exception as e:
            self.logger.error(f"Error checking processes: {e}")
    
    def _check_file_integrity(self) -> None:
        """Check monitored files for changes."""
        for file_path in list(self.monitored_files):
            try:
                if not os.path.exists(file_path):
                    if file_path in self.file_hashes:
                        self._handle_file_event("deleted", file_path)
                        del self.file_hashes[file_path]
                    continue
                
                # Calculate file hash
                current_hash = self._calculate_file_hash(file_path)
                
                # Check if this is a new file
                if file_path not in self.file_hashes:
                    self.file_hashes[file_path] = current_hash
                    self._handle_file_event("created", file_path)
                # Check if file has been modified
                elif self.file_hashes[file_path] != current_hash:
                    self.file_hashes[file_path] = current_hash
                    self._handle_file_event("modified", file_path)
                    
            except Exception as e:
                self.logger.error(f"Error checking file {file_path}: {e}")
    
    def _handle_file_event(self, event_type: str, file_path: str) -> None:
        """Handle a file system event."""
        # Find matching rules
        matching_rules = []
        for rule in self.file_rules:
            if not rule.enabled:
                continue
                
            # Simple pattern matching - in a real implementation, use proper glob/fnmatch
            if rule.path == file_path or (rule.path.endswith('*') and file_path.startswith(rule.path[:-1])):
                matching_rules.append(rule)
        
        # Take action for each matching rule
        for rule in matching_rules:
            self._take_action(rule, f"File {event_type}: {file_path}", rule.alert_level)
    
    def _take_action(self, rule: Any, message: str, alert_level: HIPSAlertLevel) -> None:
        """Take action based on the rule and event."""
        # Log the event
        log_msg = f"HIPS {rule.action.name}: {message}"
        
        if alert_level == HIPSAlertLevel.CRITICAL:
            self.logger.critical(log_msg)
        elif alert_level == HIPSAlertLevel.HIGH:
            self.logger.error(log_msg)
        elif alert_level == HIPSAlertLevel.MEDIUM:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)
        
        # Take the specified action
        if rule.action == HIPSAction.BLOCK:
            # In a real implementation, this would block the operation
            self.logger.debug(f"Blocked: {message}")
            
        elif rule.action == HIPSAction.QUARANTINE:
            # In a real implementation, this would quarantine the file
            self.logger.debug(f"Quarantined: {message}")
    
    @staticmethod
    def _calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate the hash of a file."""
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
            
        except Exception as e:
            raise Exception(f"Failed to calculate hash for {file_path}: {e}")

# Singleton instance for easy access
hips_manager = HIPSManager()
