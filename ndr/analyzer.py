"""
Network Traffic Analysis Module

Provides advanced threat detection and analysis capabilities for network traffic.
Uses signature-based detection, behavioral analysis, and machine learning to
identify malicious activity.
"""
import asyncio
import logging
import re
import ipaddress
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import hashlib
from pathlib import Path

import yara
from scapy.all import IP, TCP, UDP, ICMP, IPv6

from .models.alert import NetworkAlert, AlertSeverity
from .models.flow import NetworkFlow
from .utils.net_utils import is_private_ip, is_rfc1918

logger = logging.getLogger('edr.network.analyzer')

@dataclass
class AnalyzerConfig:
    """Configuration for the network analyzer."""
    # Detection settings
    enable_signature_detection: bool = True
    enable_behavioral_analysis: bool = True
    enable_machine_learning: bool = True
    
    # Thresholds
    port_scan_threshold: int = 20  # Ports per minute
    host_scan_threshold: int = 50  # Hosts per minute
    brute_force_threshold: int = 10  # Attempts per minute
    
    # File paths
    rules_dir: str = "rules/network"
    model_dir: str = "models/network"
    
    # Update intervals (seconds)
    signature_update_interval: int = 3600  # 1 hour
    model_update_interval: int = 86400  # 24 hours

class NetworkAnalyzer:
    """
    Analyzes network traffic for security threats and anomalies.
    """
    
    def __init__(self, config: Optional[AnalyzerConfig] = None):
        """Initialize the network analyzer."""
        self.config = config or AnalyzerConfig()
        self.active = False
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        
        # Detection engines
        self.signature_rules: List[yara.Rules] = []
        self.behavioral_profiles: Dict[str, Any] = {}
        self.ml_models: Dict[str, Any] = {}
        
        # State for behavioral analysis
        self.host_activity: Dict[str, Dict[str, Any]] = {}  # Key: host_ip
        self.port_activity: Dict[Tuple[str, int], Dict[str, Any]] = {}  # Key: (host_ip, port)
        self.connection_attempts: Dict[Tuple[str, str, int], int] = {}  # Key: (src_ip, dst_ip, port)
        
        # Initialize detection engines
        self._init_signature_engine()
        self._init_behavioral_engine()
        self._init_ml_engine()
    
    def _init_signature_engine(self):
        """Initialize the signature-based detection engine."""
        try:
            rules_dir = Path(self.config.rules_dir)
            if not rules_dir.exists():
                logger.warning(f"Rules directory not found: {rules_dir}")
                return
                
            # Load YARA rules from directory
            rule_files = list(rules_dir.glob('*.yar'))
            if not rule_files:
                logger.warning(f"No YARA rules found in {rules_dir}")
                return
                
            for rule_file in rule_files:
                try:
                    rules = yara.compile(filepath=str(rule_file))
                    self.signature_rules.append(rules)
                    logger.info(f"Loaded signature rules from {rule_file}")
                except yara.Error as e:
                    logger.error(f"Error loading YARA rule {rule_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error initializing signature engine: {e}")
    
    def _init_behavioral_engine(self):
        """Initialize the behavioral analysis engine."""
        # Load behavioral profiles if they exist
        try:
            profiles_file = Path(self.config.rules_dir) / "behavioral_profiles.json"
            if profiles_file.exists():
                with open(profiles_file, 'r') as f:
                    self.behavioral_profiles = json.load(f)
                logger.info(f"Loaded {len(self.behavioral_profiles)} behavioral profiles")
        except Exception as e:
            logger.error(f"Error loading behavioral profiles: {e}")
    
    def _init_ml_engine(self):
        """Initialize the machine learning engine."""
        # This would load pre-trained ML models for anomaly detection
        # For now, we'll just log that it's not implemented
        logger.info("Machine learning engine initialization placeholder")
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for security alerts."""
        self.alert_callbacks.append(callback)
    
    async def analyze_flow(self, flow: NetworkFlow) -> Optional[NetworkAlert]:
        """
        Analyze a network flow for security threats.
        
        Args:
            flow: The network flow to analyze
            
        Returns:
            NetworkAlert if a threat is detected, None otherwise
        """
        if not self.active:
            return None
            
        alerts = []
        
        # 1. Signature-based detection
        if self.config.enable_signature_detection:
            sig_alerts = await self._detect_signatures(flow)
            if sig_alerts:
                alerts.extend(sig_alerts)
        
        # 2. Behavioral analysis
        if self.config.enable_behavioral_analysis:
            behavior_alerts = await self._analyze_behavior(flow)
            if behavior_alerts:
                alerts.extend(behavior_alerts)
        
        # 3. Machine learning detection
        if self.config.enable_machine_learning and self.ml_models:
            ml_alerts = await self._detect_with_ml(flow)
            if ml_alerts:
                alerts.extend(ml_alerts)
        
        # Return the highest severity alert, or None if no alerts
        if alerts:
            return max(alerts, key=lambda a: a.severity.value)
        return None
    
    async def _detect_signatures(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Detect threats using signature-based detection."""
        alerts = []
        
        # Check for known malicious IPs and domains
        if self._is_malicious_destination(flow):
            alerts.append(NetworkAlert(
                title="Connection to Known Malicious Destination",
                description=f"Connection to known malicious destination {flow.dst_ip}:{flow.dst_port}",
                severity=AlertSeverity.HIGH,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'threat_type': 'malicious_destination',
                    'confidence': 'high'
                }
            ))
        
        # Check for suspicious ports
        if self._is_suspicious_port(flow.dst_port, flow.protocol):
            alerts.append(NetworkAlert(
                title="Suspicious Port Activity",
                description=f"Connection to suspicious port {flow.dst_port}/{flow.protocol}",
                severity=AlertSeverity.MEDIUM,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'threat_type': 'suspicious_port',
                    'port': flow.dst_port,
                    'protocol': flow.protocol
                }
            ))
        
        return alerts
    
    def _is_malicious_destination(self, flow: NetworkFlow) -> bool:
        """Check if the destination is known to be malicious."""
        # This would typically query a threat intelligence feed or local database
        # For now, we'll just check some known bad IPs and domains
        known_bad_ips = {
            '1.1.1.1',  # Example - replace with real threat intel
            '2.2.2.2',
            '3.3.3.3'
        }
        
        known_bad_domains = {
            'example-malicious-domain.com',
            'another-bad-site.org'
        }
        
        # Check IP
        if flow.dst_ip in known_bad_ips:
            return True
            
        # Check domain (if available in metadata)
        if hasattr(flow, 'metadata') and flow.metadata:
            for domain in known_bad_domains:
                if 'host' in flow.metadata and domain in flow.metadata['host']:
                    return True
                if 'dns' in flow.metadata and 'query' in flow.metadata['dns']:
                    if domain in flow.metadata['dns']['query']:
                        return True
        
        return False
    
    def _is_suspicious_port(self, port: Optional[int], protocol: str) -> bool:
        """Check if a port is suspicious for a given protocol."""
        if port is None:
            return False
            
        # Common suspicious ports
        suspicious_ports = {
            4444,  # Metasploit
            8080,  # Common web proxy/C2
            9001,  # Tor
            31337, # Back Orifice
            3389,  # RDP
            22,    # SSH - often targeted
            23,    # Telnet - insecure
            21,    # FTP - often targeted
            25,    # SMTP - often abused
            1433,  # MS SQL
            3306,  # MySQL
            5432,  # PostgreSQL
            27017, # MongoDB
            11211, # Memcached
            2049,  # NFS
            873,   # rsync
            161,   # SNMP
            389,   # LDAP
            445,   # SMB
            135,   # MS RPC
            139,   # NetBIOS
        }
        
        return port in suspicious_ports
    
    async def _analyze_behavior(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Analyze network behavior for anomalies."""
        alerts = []
        now = datetime.utcnow()
        
        # Update host activity
        self._update_host_activity(flow, now)
        
        # Check for port scanning
        if self._is_port_scan(flow, now):
            alerts.append(NetworkAlert(
                title="Port Scanning Detected",
                description=f"Port scanning activity detected from {flow.src_ip}",
                severity=AlertSeverity.HIGH,
                source_ip=flow.src_ip,
                metadata={
                    'threat_type': 'port_scan',
                    'scanned_ports': len(self.host_activity[flow.src_ip]['scanned_ports']),
                    'time_window': self.config.port_scan_threshold
                }
            ))
        
        # Check for host scanning
        if self._is_host_scan(flow, now):
            alerts.append(NetworkAlert(
                title="Host Scanning Detected",
                description=f"Host scanning activity detected from {flow.src_ip}",
                severity=AlertSeverity.HIGH,
                source_ip=flow.src_ip,
                metadata={
                    'threat_type': 'host_scan',
                    'scanned_hosts': len(self.host_activity[flow.src_ip]['scanned_hosts']),
                    'time_window': self.config.host_scan_threshold
                }
            ))
        
        # Check for brute force attempts
        if self._is_brute_force(flow, now):
            alerts.append(NetworkAlert(
                title="Brute Force Attempt Detected",
                description=f"Possible brute force attempt from {flow.src_ip} to {flow.dst_ip}:{flow.dst_port}",
                severity=AlertSeverity.HIGH,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                destination_port=flow.dst_port,
                metadata={
                    'threat_type': 'brute_force',
                    'attempts': self.connection_attempts.get((flow.src_ip, flow.dst_ip, flow.dst_port), 0),
                    'time_window': self.config.brute_force_threshold
                }
            ))
        
        return alerts
    
    def _update_host_activity(self, flow: NetworkFlow, timestamp: datetime):
        """Update host activity tracking."""
        # Initialize host activity if not exists
        if flow.src_ip not in self.host_activity:
            self.host_activity[flow.src_ip] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned_ports': set(),
                'scanned_hosts': set(),
                'connection_attempts': {}
            }
        
        # Update last seen time
        self.host_activity[flow.src_ip]['last_seen'] = timestamp
        
        # Track scanned ports
        if flow.dst_port:
            self.host_activity[flow.src_ip]['scanned_ports'].add(flow.dst_port)
        
        # Track scanned hosts
        self.host_activity[flow.src_ip]['scanned_hosts'].add(flow.dst_ip)
        
        # Track connection attempts
        key = (flow.src_ip, flow.dst_ip, flow.dst_port or 0)
        self.connection_attempts[key] = self.connection_attempts.get(key, 0) + 1
    
    def _is_port_scan(self, flow: NetworkFlow, timestamp: datetime) -> bool:
        """Check if the activity indicates a port scan."""
        if flow.src_ip not in self.host_activity:
            return False
            
        time_window = timestamp - timedelta(seconds=60)  # 1 minute window
        host_activity = self.host_activity[flow.src_ip]
        
        # Check if we've seen too many ports in the time window
        if len(host_activity['scanned_ports']) > self.config.port_scan_threshold:
            if host_activity['last_seen'] - host_activity['first_seen'] < timedelta(seconds=60):
                return True
                
        return False
    
    def _is_host_scan(self, flow: NetworkFlow, timestamp: datetime) -> bool:
        """Check if the activity indicates a host scan."""
        if flow.src_ip not in self.host_activity:
            return False
            
        time_window = timestamp - timedelta(seconds=60)  # 1 minute window
        host_activity = self.host_activity[flow.src_ip]
        
        # Check if we've seen too many hosts in the time window
        if len(host_activity['scanned_hosts']) > self.config.host_scan_threshold:
            if host_activity['last_seen'] - host_activity['first_seen'] < timedelta(seconds=60):
                return True
                
        return False
    
    def _is_brute_force(self, flow: NetworkFlow, timestamp: datetime) -> bool:
        """Check if the activity indicates a brute force attempt."""
        if not flow.dst_port:
            return False
            
        key = (flow.src_ip, flow.dst_ip, flow.dst_port)
        attempts = self.connection_attempts.get(key, 0)
        
        # Check if we've seen too many connection attempts to the same service
        if attempts > self.config.brute_force_threshold:
            return True
            
        return False
    
    async def _detect_with_ml(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Detect anomalies using machine learning models."""
        # Placeholder for ML-based detection
        # In a real implementation, this would use pre-trained models to detect anomalies
        return []
    
    async def start(self):
        """Start the network analyzer."""
        self.active = True
        logger.info("Network analyzer started")
    
    async def stop(self):
        """Stop the network analyzer."""
        self.active = False
        logger.info("Network analyzer stopped")
