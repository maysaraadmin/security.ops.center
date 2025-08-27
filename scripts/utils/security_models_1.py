from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum

class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AlertStatus(Enum):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"

@dataclass
class SIEMEvent:
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    description: str
    raw_data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: AlertStatus = AlertStatus.NEW

@dataclass
class EDREvent:
    timestamp: datetime
    endpoint_id: str
    process_name: str
    process_id: int
    parent_process: str
    command_line: str
    user: str
    severity: Severity
    detection_type: str
    details: Dict[str, Any]
    status: AlertStatus = AlertStatus.NEW

@dataclass
class NDREvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_size: int
    flags: str
    severity: Severity
    detection_type: str
    details: Dict[str, Any]

@dataclass
class DLPEvent:
    timestamp: datetime
    data_type: str
    source: str
    destination: str
    user: str
    severity: Severity
    policy_name: str
    action_taken: str
    details: Dict[str, Any]

@dataclass
class FIMEvent:
    timestamp: datetime
    file_path: str
    change_type: str  # created, modified, deleted, permissions_changed
    user: str
    previous_hash: Optional[str] = None
    new_hash: Optional[str] = None
    severity: Severity = Severity.INFO
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HIPSEvent:
    timestamp: datetime
    host: str
    detection_type: str
    severity: Severity
    description: str
    process_info: Dict[str, Any]
    mitigation_applied: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NIPSEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    attack_type: str
    severity: Severity
    action_taken: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DashboardMetrics:
    siem_metrics: Dict[str, Any]
    edr_metrics: Dict[str, Any]
    ndr_metrics: Dict[str, Any]
    dlp_metrics: Dict[str, Any]
    fim_metrics: Dict[str, Any]
    hips_metrics: Dict[str, Any]
    nips_metrics: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
