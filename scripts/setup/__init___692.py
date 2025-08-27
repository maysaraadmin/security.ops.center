"""
EDR Detection Engine

This module implements behavioral threat detection and alerting capabilities.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto

logger = logging.getLogger('edr.detection')

class Severity(Enum):
    """Severity levels for detected threats."""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class DetectionRule:
    """Base class for detection rules."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    
    def match(self, event: Dict[str, Any]) -> bool:
        """Check if the rule matches the given event."""
        raise NotImplementedError("Subclasses must implement match()")

@dataclass
class SignatureRule(DetectionRule):
    """Rule that matches specific signatures or patterns."""
    signatures: List[str] = field(default_factory=list)
    
    def match(self, event: Dict[str, Any]) -> bool:
        if not self.signatures:
            return False
            
        # Check each signature against the event
        for signature in self.signatures:
            if self._matches_signature(event, signature):
                return True
        return False
    
    def _matches_signature(self, event: Dict[str, Any], signature: str) -> bool:
        """Check if the event matches the given signature."""
        # This is a simplified implementation. In a real EDR, this would be more sophisticated.
        for value in event.values():
            if isinstance(value, str) and signature.lower() in value.lower():
                return True
        return False

@dataclass
class BehavioralRule(DetectionRule):
    """Rule that matches based on behavioral patterns."""
    condition: Callable[[Dict[str, Any]], bool]
    
    def match(self, event: Dict[str, Any]) -> bool:
        try:
            return self.condition(event)
        except Exception as e:
            logger.error(f"Error evaluating behavioral rule {self.rule_id}: {e}")
            return False

class DetectionEngine:
    """Core detection engine for identifying threats."""
    
    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        self.rules: Dict[str, DetectionRule] = {}
        self.alert_handlers: List[Callable[[Dict[str, Any]], None]] = []
        
        # Add default rules if none provided
        if rules is None:
            rules = self._get_default_rules()
            
        for rule in rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule to the engine."""
        self.rules[rule.rule_id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a detection rule by ID."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def add_alert_handler(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Add a callback function to handle alerts."""
        self.alert_handlers.append(handler)
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through all enabled rules."""
        alerts = []
        
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
                
            try:
                if rule.match(event):
                    alert = self._create_alert(rule, event)
                    alerts.append(alert)
                    
                    # Notify all alert handlers
                    for handler in self.alert_handlers:
                        try:
                            handler(alert)
                        except Exception as e:
                            logger.error(f"Error in alert handler: {e}")
                            
            except Exception as e:
                logger.error(f"Error processing rule {rule_id}: {e}")
        
        return alerts
    
    def _create_alert(self, rule: DetectionRule, event: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert from a rule match and event."""
        return {
            "alert_id": f"alert_{datetime.utcnow().timestamp()}",
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.name,
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "tags": rule.tags,
            "status": "new"
        }
    
    def _get_default_rules(self) -> List[DetectionRule]:
        """Get a list of default detection rules."""
        return [
            # Example: Detect suspicious process execution
            BehavioralRule(
                rule_id="proc_suspicious_execution",
                name="Suspicious Process Execution",
                description="Detects execution of processes from suspicious locations",
                severity=Severity.HIGH,
                tags=["process", "execution", "suspicious"],
                condition=lambda e: (
                    e.get("event_type") == "process_start" and
                    any(s in e.get("image_path", "").lower() 
                        for s in ["temp", "appdata", "downloads"])
                )
            ),
            
            # Example: Detect multiple failed login attempts
            BehavioralRule(
                rule_id="auth_failed_logins",
                name="Multiple Failed Login Attempts",
                description="Detects multiple failed login attempts from the same source",
                severity=Severity.MEDIUM,
                tags=["authentication", "brute_force"],
                condition=lambda e: (
                    e.get("event_type") == "auth_failed" and
                    e.get("count", 0) > 5  # More than 5 failed attempts
                )
            ),
            
            # Example: Detect suspicious network connections
            BehavioralRule(
                rule_id="net_suspicious_connection",
                name="Suspicious Network Connection",
                description="Detects connections to known malicious IPs or domains",
                severity=Severity.HIGH,
                tags=["network", "suspicious"],
                condition=lambda e: (
                    e.get("event_type") == "network_connection" and
                    any(e.get("remote_ip", "").startswith(prefix) 
                        for prefix in ["10.0.0.", "192.168."])
                )
            )
        ]
