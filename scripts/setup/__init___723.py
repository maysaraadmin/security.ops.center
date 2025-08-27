"""
HIPS Data Models.

This module defines the data models used by the HIPS service.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Pattern, Any, Set, Union
from pathlib import Path

from src.common.constants import Severity, Action

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
    alert_level: HIPSAlertLevel = HIPSAlertLevel.MEIDUM
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'process_name': self.process_name,
            'process_path': self.process_path,
            'parent_process': self.parent_process,
            'command_line': self.command_line.pattern if self.command_line else None,
            'action': self.action.name,
            'alert_level': self.alert_level.name,
            'enabled': self.enabled,
            'type': 'process'
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HIPSProcessRule':
        """Create rule from dictionary."""
        import re
        
        command_line = data.get('command_line')
        if command_line and isinstance(command_line, str):
            command_line = re.compile(command_line, re.IGNORECASE)
            
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data.get('description', ''),
            process_name=data.get('process_name'),
            process_path=data.get('process_path'),
            parent_process=data.get('parent_process'),
            command_line=command_line,
            action=HIPSAction[data.get('action', 'ALERT')],
            alert_level=HIPSAlertLevel[data.get('alert_level', 'MEDIUM')],
            enabled=data.get('enabled', True)
        )

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
    recursive: bool = False
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'path': self.path,
            'pattern': self.pattern.pattern if self.pattern else None,
            'action': self.action.name,
            'alert_level': self.alert_level.name,
            'monitor_reads': self.monitor_reads,
            'monitor_writes': self.monitor_writes,
            'monitor_executes': self.monitor_executes,
            'recursive': self.recursive,
            'enabled': self.enabled,
            'type': 'file'
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HIPSFileRule':
        """Create rule from dictionary."""
        import re
        
        pattern = data.get('pattern')
        if pattern and isinstance(pattern, str):
            pattern = re.compile(pattern, re.IGNORECASE)
            
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data.get('description', ''),
            path=data['path'],
            pattern=pattern,
            action=HIPSAction[data.get('action', 'ALERT')],
            alert_level=HIPSAlertLevel[data.get('alert_level', 'MEDIUM')],
            monitor_reads=data.get('monitor_reads', False),
            monitor_writes=data.get('monitor_writes', True),
            monitor_executes=data.get('monitor_executes', True),
            recursive=data.get('recursive', False),
            enabled=data.get('enabled', True)
        )

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
    recursive: bool = False
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'key_path': self.key_path,
            'value_name': self.value_name,
            'value_pattern': self.value_pattern.pattern if self.value_pattern else None,
            'action': self.action.name,
            'alert_level': self.alert_level.name,
            'monitor_reads': self.monitor_reads,
            'monitor_writes': self.monitor_writes,
            'monitor_deletes': self.monitor_deletes,
            'recursive': self.recursive,
            'enabled': self.enabled,
            'type': 'registry'
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HIPSRegistryRule':
        """Create rule from dictionary."""
        import re
        
        value_pattern = data.get('value_pattern')
        if value_pattern and isinstance(value_pattern, str):
            value_pattern = re.compile(value_pattern, re.IGNORECASE)
            
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data.get('description', ''),
            key_path=data['key_path'],
            value_name=data.get('value_name'),
            value_pattern=value_pattern,
            action=HIPSAction[data.get('action', 'ALERT')],
            alert_level=HIPSAlertLevel[data.get('alert_level', 'MEDIUM')],
            monitor_reads=data.get('monitor_reads', False),
            monitor_writes=data.get('monitor_writes', True),
            monitor_deletes=data.get('monitor_deletes', True),
            recursive=data.get('recursive', False),
            enabled=data.get('enabled', True)
        )

@dataclass
class HIPSAlert:
    """Represents a HIPS alert."""
    alert_id: str
    rule_id: str
    rule_name: str
    timestamp: datetime
    message: str
    severity: HIPSAlertLevel
    action_taken: HIPSAction
    source: str = 'hips'
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'timestamp': self.timestamp.isoformat(),
            'message': self.message,
            'severity': self.severity.name,
            'action_taken': self.action_taken.name,
            'source': self.source,
            'details': self.details
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HIPSAlert':
        """Create alert from dictionary."""
        from datetime import datetime
        
        if isinstance(data['timestamp'], str):
            timestamp = datetime.fromisoformat(data['timestamp'])
        else:
            timestamp = data['timestamp']
            
        return cls(
            alert_id=data['alert_id'],
            rule_id=data['rule_id'],
            rule_name=data['rule_name'],
            timestamp=timestamp,
            message=data['message'],
            severity=HIPSAlertLevel[data['severity']],
            action_taken=HIPSAction[data['action_taken']],
            source=data.get('source', 'hips'),
            details=data.get('details', {})
        )

@dataclass
class HIPSStats:
    """HIPS service statistics."""
    start_time: datetime
    rules_loaded: int = 0
    rules_active: int = 0
    process_rules: int = 0
    file_rules: int = 0
    registry_rules: int = 0
    alerts_triggered: int = 0
    files_monitored: int = 0
    processes_blocked: int = 0
    files_quarantined: int = 0
    registry_changes_blocked: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        return {
            'start_time': self.start_time.isoformat(),
            'uptime': (datetime.now() - self.start_time).total_seconds(),
            'rules_loaded': self.rules_loaded,
            'rules_active': self.rules_active,
            'process_rules': self.process_rules,
            'file_rules': self.file_rules,
            'registry_rules': self.registry_rules,
            'alerts_triggered': self.alerts_triggered,
            'files_monitored': self.files_monitored,
            'processes_blocked': self.processes_blocked,
            'files_quarantined': self.files_quarantined,
            'registry_changes_blocked': self.registry_changes_blocked,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage
        }
