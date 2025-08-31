"""
Threat detection engine and rules for the EDR system.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Type, Union
import yaml
import json
import re
import os
from pathlib import Path
import importlib.util
import inspect
from datetime import datetime, timedelta

from .event import EDREvent, EventType, EventSeverity, ThreatInfo
from .base import EDRBase

class DetectionType(Enum):
    """Types of detection rules."""
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    ANOMALY = "anomaly"
    HEURISTIC = "heuristic"
    MACHINE_LEARNING = "machine_learning"

@dataclass
class DetectionRule:
    """Base class for detection rules."""
    rule_id: str
    name: str
    description: str
    detection_type: DetectionType
    severity: EventSeverity
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    def match(self, event: EDREvent) -> Optional[ThreatInfo]:
        """Check if the rule matches the given event."""
        raise NotImplementedError("Subclasses must implement match()")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'detection_type': self.detection_type.value,
            'severity': self.severity.name,
            'enabled': self.enabled,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionRule':
        """Create a rule from a dictionary."""
        raise NotImplementedError("Subclasses must implement from_dict()")
    
    def to_json(self) -> str:
        """Convert the rule to JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'DetectionRule':
        """Create a rule from JSON."""
        return cls.from_dict(json.loads(json_str))

@dataclass
class SignatureRule(DetectionRule):
    """Signature-based detection rule."""
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    
    def match(self, event: EDREvent) -> Optional[ThreatInfo]:
        """Check if the event matches any of the signatures."""
        if not self.enabled:
            return None
            
        for sig in self.signatures:
            if self._matches_signature(event, sig):
                return ThreatInfo(
                    name=self.name,
                    description=f"{self.description}\n\nMatched signature: {sig.get('name', 'unknown')}",
                    severity=self.severity,
                    confidence=0.9,  # High confidence for signature matches
                    mitre_techniques=sig.get('mitre_techniques', [])
                )
        return None
    
    def _matches_signature(self, event: EDREvent, signature: Dict[str, Any]) -> bool:
        """Check if the event matches the given signature."""
        # Check event type
        if 'event_type' in signature and event.event_type != EventType(signature['event_type']):
            return False
            
        # Check process attributes
        if 'process' in signature and event.process:
            for attr, pattern in signature['process'].items():
                if not hasattr(event.process, attr):
                    return False
                value = str(getattr(event.process, attr, '')).lower()
                if not re.search(pattern, value, re.IGNORECASE):
                    return False
                    
        # Check file attributes
        if 'file' in signature and event.file:
            for attr, pattern in signature['file'].items():
                if not hasattr(event.file, attr):
                    return False
                value = str(getattr(event.file, attr, '')).lower()
                if not re.search(pattern, value, re.IGNORECASE):
                    return False
                    
        # Check network attributes
        if 'network' in signature and event.network:
            for attr, pattern in signature['network'].items():
                if not hasattr(event.network, attr):
                    return False
                value = str(getattr(event.network, attr, '')).lower()
                if not re.search(pattern, value, re.IGNORECASE):
                    return False
                    
        # All checks passed
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        result = super().to_dict()
        result['signatures'] = self.signatures
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureRule':
        """Create a rule from a dictionary."""
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data['description'],
            detection_type=DetectionType(data['detection_type']),
            severity=EventSeverity[data['severity']],
            enabled=data.get('enabled', True),
            tags=data.get('tags', []),
            signatures=data.get('signatures', [])
        )

@dataclass
class BehavioralRule(DetectionRule):
    """Behavioral detection rule."""
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    time_window: int = 300  # seconds
    
    def __post_init__(self):
        """Initialize the rule."""
        self.detection_type = DetectionType.BEHAVIORAL
        self._event_history = []  # In-memory event history (in production, use a proper database)
    
    def match(self, event: EDREvent) -> Optional[ThreatInfo]:
        """Check if the event matches the behavioral rule."""
        if not self.enabled:
            return None
            
        # Add event to history
        self._event_history.append((datetime.now(), event))
        
        # Clean up old events
        cutoff = datetime.now() - timedelta(seconds=self.time_window)
        self._event_history = [(ts, e) for ts, e in self._event_history if ts >= cutoff]
        
        # Check conditions
        for condition in self.conditions:
            if self._check_condition(condition):
                return ThreatInfo(
                    name=self.name,
                    description=f"{self.description}\n\nBehavioral condition met: {condition.get('description', '')}",
                    severity=self.severity,
                    confidence=0.8,  # Slightly lower confidence than signatures
                    mitre_techniques=condition.get('mitre_techniques', [])
                )
        return None
    
    def _check_condition(self, condition: Dict[str, Any]) -> bool:
        """Check if a behavioral condition is met."""
        event_type = EventType(condition['event_type'])
        count = condition.get('count', 1)
        timeframe = condition.get('timeframe', self.time_window)
        
        # Count matching events in the time window
        matches = 0
        for ts, event in self._event_history:
            if event.event_type == event_type:
                if self._matches_event_properties(event, condition.get('properties', {})):
                    matches += 1
                    if matches >= count:
                        return True
        
        return False
    
    def _matches_event_properties(self, event: EDREvent, properties: Dict[str, Any]) -> bool:
        """Check if an event matches the given properties."""
        for entity_type, props in properties.items():
            entity = getattr(event, entity_type, None)
            if not entity:
                return False
                
            for prop, pattern in props.items():
                if not hasattr(entity, prop):
                    return False
                    
                value = str(getattr(entity, prop, '')).lower()
                if not re.search(pattern, value, re.IGNORECASE):
                    return False
                    
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        result = super().to_dict()
        result.update({
            'conditions': self.conditions,
            'time_window': self.time_window
        })
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehavioralRule':
        """Create a rule from a dictionary."""
        return cls(
            rule_id=data['rule_id'],
            name=data['name'],
            description=data['description'],
            detection_type=DetectionType.BEHAVIORAL,
            severity=EventSeverity[data['severity']],
            enabled=data.get('enabled', True),
            tags=data.get('tags', []),
            conditions=data.get('conditions', []),
            time_window=data.get('time_window', 300)
        )

class DetectionEngine(EDRBase):
    """Engine for detecting threats using multiple detection rules."""
    
    def __init__(self, config):
        """Initialize the detection engine."""
        super().__init__(config)
        self.rules: Dict[str, DetectionRule] = {}
        self._load_rules()
    
    def _load_rules(self):
        """Load detection rules from the configured directory."""
        # Handle both dictionary and object-style config access
        if hasattr(self.config, 'detection_rules_path'):
            rules_path = self.config.detection_rules_path
        elif isinstance(self.config, dict) and 'detection_rules_path' in self.config:
            rules_path = self.config['detection_rules_path']
        else:
            # Default path if not specified
            rules_path = os.path.join(os.path.dirname(__file__), '..', 'rules')
            
        rules_dir = Path(rules_path)
        if not rules_dir.exists():
            self.logger.warning(f"Rules directory not found: {rules_dir}")
            # Create default rules directory
            rules_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created default rules directory at: {rules_dir}")
            # Add a default rule
            self._create_default_rule()
            return
            
        # Load YAML rules
        rule_files = list(rules_dir.glob('**/*.yaml')) + list(rules_dir.glob('**/*.json'))
        
        if not rule_files:
            self.logger.warning(f"No rule files found in {rules_dir}")
            # Add a default rule if no rules found
            self._create_default_rule()
            return
            
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    if rule_file.suffix.lower() == '.yaml':
                        rule_data = yaml.safe_load(f)
                    else:  # .json
                        rule_data = json.load(f)
                    
                    # Handle both single rule and list of rules
                    if isinstance(rule_data, list):
                        for rule_item in rule_data:
                            rule = self._create_rule(rule_item)
                            if rule:
                                self.rules[rule.rule_id] = rule
                                self.logger.debug(f"Loaded rule: {rule.name} ({rule.rule_id})")
                    else:
                        rule = self._create_rule(rule_data)
                        if rule:
                            self.rules[rule.rule_id] = rule
                            self.logger.debug(f"Loaded rule: {rule.name} ({rule.rule_id})")
            except Exception as e:
                self.logger.error(f"Error loading rule from {rule_file}: {e}")
        
        # Load Python rules
        for rule_file in rules_dir.glob('**/*.py'):
            if rule_file.name == '__init__.py':
                continue
                
            try:
                # Import the module
                spec = importlib.util.spec_from_file_location(
                    f"edr.rules.{rule_file.stem}",
                    rule_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find all rule classes in the module
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                            issubclass(obj, DetectionRule) and 
                            obj != DetectionRule):
                        rule = obj()
                        self.rules[rule.rule_id] = rule
                        self.logger.debug(f"Loaded Python rule: {rule.name} ({rule.rule_id})")
                        
            except Exception as e:
                self.logger.error(f"Error loading Python rule from {rule_file}: {e}")
    
    def _create_rule(self, rule_data: Dict[str, Any]) -> Optional[DetectionRule]:
        """Create a rule from a dictionary."""
        try:
            # Handle both 'id' and 'rule_id' fields for backward compatibility
            if 'id' in rule_data and 'rule_id' not in rule_data:
                rule_data['rule_id'] = rule_data['id']
                
            if 'rule_id' not in rule_data:
                self.logger.error("Rule is missing required 'rule_id' field")
                return None
                
            rule_type = DetectionType(rule_data.get('detection_type', 'signature').lower())
            
            if rule_type == DetectionType.SIGNATURE:
                return SignatureRule.from_dict(rule_data)
            elif rule_type == DetectionType.BEHAVIORAL:
                return BehavioralRule.from_dict(rule_data)
            else:
                self.logger.warning(f"Unsupported rule type: {rule_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating rule: {e}")
            import traceback
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
            return None
    
    def _create_default_rule(self) -> None:
        """Create a default rule when no rules are found."""
        default_rule = {
            'rule_id': 'default_rule_1',
            'name': 'Default Suspicious Process Detection',
            'description': 'Detects common suspicious processes',
            'detection_type': 'signature',
            'severity': 'HIGH',
            'enabled': True,
            'signatures': [
                {
                    'process_name': ['mimikatz.exe', 'procdump.exe', 'psexec.exe', 'cobaltstrike.exe']
                }
            ]
        }
        try:
            rule = self._create_rule(default_rule)
            if rule:
                self.rules[rule.rule_id] = rule
                self.logger.info("Created default detection rule")
        except Exception as e:
            self.logger.error(f"Failed to create default rule: {e}")
                
    def process_event(self, event: EDREvent) -> List[ThreatInfo]:
        """Process an event through all enabled rules."""
        threats = []
        
        for rule in self.rules.values():
            try:
                threat = rule.match(event)
                if threat:
                    threats.append(threat)
            except Exception as e:
                self.logger.error(f"Error in rule {rule.rule_id}: {e}")
                
        return threats
    
    def add_rule(self, rule: DetectionRule):
        """Add a rule to the engine."""
        self.rules[rule.rule_id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a rule by ID."""
        return self.rules.get(rule_id)
    
    def list_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all rules."""
        return [
            rule.to_dict()
            for rule in self.rules.values()
            if not enabled_only or rule.enabled
        ]
