"""
Alert Management and Threat Prioritization for EDR.
Handles alert generation, enrichment, and prioritization based on MITRE ATT&CK framework.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json
import logging
import hashlib
from enum import Enum

# MITRE ATT&CK Tactics by priority (lower number = higher priority)
MITRE_TACTICS = {
    # Initial Access
    'TA0001': {'name': 'Initial Access', 'severity': 8, 'priority': 'High'},
    # Execution
    'TA0002': {'name': 'Execution', 'severity': 7, 'priority': 'High'},
    # Persistence
    'TA0003': {'name': 'Persistence', 'severity': 9, 'priority': 'Critical'},
    # Privilege Escalation
    'TA0004': {'name': 'Privilege Escalation', 'severity': 9, 'priority': 'Critical'},
    # Defense Evasion
    'TA0005': {'name': 'Defense Evasion', 'severity': 8, 'priority': 'High'},
    # Credential Access
    'TA0006': {'name': 'Credential Access', 'severity': 9, 'priority': 'Critical'},
    # Discovery
    'TA0007': {'name': 'Discovery', 'severity': 5, 'priority': 'Medium'},
    # Lateral Movement
    'TA0008': {'name': 'Lateral Movement', 'severity': 8, 'priority': 'High'},
    # Collection
    'TA0009': {'name': 'Collection', 'severity': 6, 'priority': 'Medium'},
    # Exfiltration
    'TA0010': {'name': 'Exfiltration', 'severity': 9, 'priority': 'Critical'},
    # Command and Control
    'TA0011': {'name': 'Command and Control', 'severity': 8, 'priority': 'High'},
    # Impact
    'TA0040': {'name': 'Impact', 'severity': 7, 'priority': 'High'},
}

class AlertStatus(str, Enum):
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    RESOLVED = 'resolved'
    FALSE_POSITIVE = 'false_positive'
    IGNORED = 'ignored'

@dataclass
class AlertContext:
    """Contextual information about the alert."""
    process: Optional[Dict[str, Any]] = None
    network: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    registry: Optional[Dict[str, Any]] = None
    user: Optional[Dict[str, Any]] = None
    endpoint: Optional[Dict[str, Any]] = None

@dataclass
class Alert:
    """Represents a security alert with MITRE ATT&CK mapping."""
    alert_id: str
    timestamp: str
    name: str
    description: str
    severity: int  # 1-10 scale
    status: AlertStatus = AlertStatus.NEW
    confidence: float = 1.0  # 0.0-1.0
    source: str = 'edr'
    tactic: Optional[Dict[str, Any]] = None
    technique: Optional[Dict[str, Any]] = None
    subtechnique: Optional[Dict[str, Any]] = None
    context: AlertContext = field(default_factory=AlertContext)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        data = asdict(self)
        data['status'] = self.status.value
        return data

    @property
    def priority(self) -> str:
        """Get priority based on severity and confidence."""
        score = self.severity * self.confidence
        if score >= 8:
            return 'Critical'
        elif score >= 6:
            return 'High'
        elif score >= 4:
            return 'Medium'
        return 'Low'

    def add_indicator(self, indicator_type: str, value: str, **kwargs):
        """Add an indicator to the alert."""
        self.indicators.append({
            'type': indicator_type,
            'value': value,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **kwargs
        })

class AlertManager:
    """Manages alert generation, enrichment, and prioritization."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the alert manager."""
        self.config = config
        self.logger = logging.getLogger('edr.alerting')
        self.alerts: Dict[str, Alert] = {}
        self._load_mitre_mappings()
    
    def _load_mitre_mappings(self) -> None:
        """Load MITRE ATT&CK techniques and sub-techniques."""
        # In a real implementation, this would load from a file or database
        self.mitre_techniques = {
            # Example techniques - would be expanded in a real implementation
            'T1059': {  # Command-Line Interface
                'tactics': ['TA0002'],  # Execution
                'name': 'Command-Line Interface',
                'description': 'Adversaries may use command-line interfaces for execution.'
            },
            'T1059.001': {  # PowerShell
                'tactics': ['TA0002'],  # Execution
                'name': 'PowerShell',
                'description': 'Adversaries may abuse PowerShell for execution.'
            },
            'T1053': {  # Scheduled Task/Job
                'tactics': ['TA0002', 'TA0003'],  # Execution, Persistence
                'name': 'Scheduled Task/Job',
                'description': 'Adversaries may abuse task scheduling to execute code.'
            },
            'T1021': {  # Remote Services
                'tactics': ['TA0008'],  # Lateral Movement
                'name': 'Remote Services',
                'description': 'Adversaries may use valid accounts to interact with remote services.'
            },
            'T1003': {  # OS Credential Dumping
                'tactics': ['TA0006'],  # Credential Access
                'name': 'OS Credential Dumping',
                'description': 'Adversaries may attempt to dump credentials from the operating system.'
            },
            'T1071': {  # Application Layer Protocol
                'tactics': ['TA0011'],  # Command and Control
                'name': 'Application Layer Protocol',
                'description': 'Adversaries may communicate using application layer protocols.'
            }
        }
    
    def create_alert_id(self, alert_data: Dict[str, Any]) -> str:
        """Generate a unique alert ID based on alert data."""
        # Create a hash of relevant alert data to generate a consistent ID
        hash_input = f"{alert_data.get('name', '')}:{alert_data.get('description', '')}"
        if 'process' in alert_data.get('context', {}):
            proc = alert_data['context']['process']
            hash_input += f":{proc.get('name', '')}:{proc.get('pid', '')}:{proc.get('command_line', '')}"
        return f"alert_{hashlib.md5(hash_input.encode()).hexdigest()}"
    
    def create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Create a new alert with MITRE ATT&CK mapping."""
        # Set default values
        alert_data.setdefault('severity', 5)
        alert_data.setdefault('confidence', 1.0)
        alert_data.setdefault('status', AlertStatus.NEW)
        
        # Generate alert ID if not provided
        if 'alert_id' not in alert_data:
            alert_data['alert_id'] = self.create_alert_id(alert_data)
        
        # Create context object if not provided
        if 'context' not in alert_data:
            alert_data['context'] = {}
        
        # Create Alert object
        alert = Alert(**alert_data)
        
        # Map to MITRE ATT&CK if technique ID is provided
        if 'technique_id' in alert_data:
            self._map_to_mitre(alert, alert_data['technique_id'])
        
        # Store alert
        self.alerts[alert.alert_id] = alert
        self.logger.info(f"Created alert: {alert.alert_id} - {alert.name} (Severity: {alert.severity})")
        
        return alert
    
    def _map_to_mitre(self, alert: Alert, technique_id: str) -> None:
        """Map alert to MITRE ATT&CK framework."""
        technique = self.mitre_techniques.get(technique_id)
        if not technique:
            self.logger.warning(f"Unknown MITRE technique ID: {technique_id}")
            return
        
        # Set technique information
        alert.technique = {
            'id': technique_id,
            'name': technique['name'],
            'description': technique['description']
        }
        
        # Set tactic information (use the first tactic for now)
        if technique['tactics']:
            tactic_id = technique['tactics'][0]
            alert.tactic = {
                'id': tactic_id,
                **MITRE_TACTICS[tactic_id]
            }
            
            # Update alert severity based on tactic if not explicitly set
            if alert.severity == 5:  # Default severity
                alert.severity = MITRE_TACTICS[tactic_id]['severity']
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self.alerts.get(alert_id)
    
    def update_alert_status(self, alert_id: str, status: AlertStatus, 
                          comment: Optional[str] = None) -> bool:
        """Update the status of an alert."""
        if alert_id not in self.alerts:
            self.logger.warning(f"Alert not found: {alert_id}")
            return False
        
        alert = self.alerts[alert_id]
        alert.status = status
        
        if comment:
            alert.metadata.setdefault('comments', []).append({
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'user': 'system',  # In a real implementation, this would be the current user
                'comment': comment,
                'status_change': status.value
            })
        
        self.logger.info(f"Updated alert {alert_id} status to {status.value}")
        return True
    
    def get_alerts(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get alerts matching the given filters."""
        if not filters:
            return [alert.to_dict() for alert in self.alerts.values()]
        
        filtered_alerts = []
        for alert in self.alerts.values():
            alert_dict = alert.to_dict()
            match = True
            
            for key, value in filters.items():
                # Handle nested fields (e.g., 'tactic.id')
                if '.' in key:
                    parts = key.split('.')
                    current = alert_dict
                    for part in parts[:-1]:
                        if part not in current:
                            match = False
                            break
                        current = current[part]
                    else:
                        if current.get(parts[-1]) != value:
                            match = False
                else:
                    if key not in alert_dict or alert_dict[key] != value:
                        match = False
                
                if not match:
                    break
            
            if match:
                filtered_alerts.append(alert_dict)
        
        # Sort by severity (descending) and timestamp (descending)
        return sorted(
            filtered_alerts,
            key=lambda x: (-x['severity'], x['timestamp'])
        )
    
    def correlate_alerts(self, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """Correlate related alerts within a time window."""
        # This is a simplified correlation example
        # In a real implementation, you would use more sophisticated correlation rules
        
        # Get recent alerts within the time window
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        recent_alerts = [
            alert for alert in self.alerts.values()
            if datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00')) > time_threshold
        ]
        
        # Group alerts by endpoint and process
        endpoint_groups: Dict[str, List[Alert]] = {}
        for alert in recent_alerts:
            endpoint_id = alert.context.endpoint.get('id') if alert.context.endpoint else 'unknown'
            endpoint_groups.setdefault(endpoint_id, []).append(alert)
        
        # Find related alerts
        correlated_incidents = []
        
        for endpoint_id, alerts in endpoint_groups.items():
            # Group by process if available
            process_groups: Dict[str, List[Alert]] = {}
            for alert in alerts:
                proc = alert.context.process
                if proc:
                    proc_id = f"{proc.get('name', '')}:{proc.get('pid', '')}"
                    process_groups.setdefault(proc_id, []).append(alert)
                else:
                    process_groups.setdefault('unknown', []).append(alert)
            
            # Create incidents for each process group
            for proc_id, proc_alerts in process_groups.items():
                if len(proc_alerts) > 1:
                    # Sort by timestamp
                    proc_alerts.sort(key=lambda x: x.timestamp)
                    
                    incident = {
                        'incident_id': f"inc_{hashlib.md5((endpoint_id + proc_id).encode()).hexdigest()}",
                        'start_time': proc_alerts[0].timestamp,
                        'end_time': proc_alerts[-1].timestamp,
                        'endpoint_id': endpoint_id,
                        'process': proc_alerts[0].context.process if proc_alerts[0].context.process else None,
                        'alerts': [alert.alert_id for alert in proc_alerts],
                        'severity': max(alert.severity for alert in proc_alerts),
                        'tactics': list(set(
                            alert.tactic['id'] for alert in proc_alerts 
                            if alert.tactic and 'id' in alert.tactic
                        )),
                        'techniques': list(set(
                            alert.technique['id'] for alert in proc_alerts 
                            if alert.technique and 'id' in alert.technique
                        ))
                    }
                    correlated_incidents.append(incident)
        
        return correlated_incidents
