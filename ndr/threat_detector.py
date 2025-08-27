"""
Threat Detection & Alerting Module

Detects malware, ransomware, C2 communications, and insider threats.
Correlates events with MITRE ATT&CK tactics for better threat classification.
"""
import asyncio
import logging
import json
import re
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Deque, Pattern, DefaultDict
from collections import defaultdict, deque
from enum import Enum
import hashlib
import dns.resolver
import yaml
from pathlib import Path

from .models.flow import NetworkFlow, FlowDirection, Protocol
from .models.alert import NetworkAlert, AlertSeverity, AlertType
from .utils.net_utils import is_private_ip, get_service_name, is_domain_suspicious

logger = logging.getLogger('ndr.threat_detector')

class ThreatType(str, Enum):
    """Types of detected threats."""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    C2 = "command_and_control"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    INSIDER_THREAT = "insider_threat"
    EXPLOITATION = "exploitation"
    PIVOTING = "pivoting"
    BRUTE_FORCE = "brute_force"
    DNS_TUNNELING = "dns_tunneling"
    PORT_SCAN = "port_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CREDENTIAL_THEFT = "credential_theft"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    EXECUTION = "execution"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    UNKNOWN = "unknown"

@dataclass
class ThreatConfig:
    """Configuration for threat detection."""
    # Detection settings
    enable_signature_detection: bool = True
    enable_behavioral_detection: bool = True
    enable_heuristic_detection: bool = True
    
    # Alert thresholds
    min_confidence: float = 0.7  # Minimum confidence to generate alert
    
    # Time windows for correlation (in seconds)
    correlation_window: int = 300  # 5 minutes
    
    # IoC update settings
    ioc_update_interval: int = 3600  # 1 hour
    
    # Data directories
    data_dir: str = "data/ndr/threats"
    ioc_dir: str = "data/ndr/iocs"
    rules_dir: str = "rules/threats"
    
    # Thresholds
    port_scan_threshold: int = 10  # Ports per host per minute
    brute_force_threshold: int = 5  # Failed auth attempts per minute
    dns_tunneling_threshold: float = 3.0  # Entropy threshold
    
    # Whitelists
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_domains: List[str] = field(default_factory=list)
    
    # MITRE ATT&CK framework
    mitre_attack_path: str = "data/mitre/attack/enterprise-attack.json"
    
    # Enable/disable specific detectors
    enable_c2_detection: bool = True
    enable_ransomware_detection: bool = True
    enable_insider_threat_detection: bool = True
    enable_dns_tunneling_detection: bool = True
    enable_port_scan_detection: bool = True

@dataclass
class IoC:
    """Indicator of Compromise (IoC)."""
    ioc_type: str  # ip, domain, hash, url, etc.
    value: str
    threat_type: ThreatType
    confidence: float
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)  # Tactic/technique IDs
    metadata: Dict[str, Any] = field(default_factory=dict)

class ThreatDetector:
    """
    Detects various types of threats in network traffic.
    Correlates events with MITRE ATT&CK framework.
    """
    
    def __init__(self, config: Optional[ThreatConfig] = None):
        """Initialize the threat detector."""
        self.config = config or ThreatConfig()
        self.active = False
        
        # State tracking
        self.iocs: Dict[str, IoC] = {}
        self.known_malicious_ips: Set[str] = set()
        self.known_malicious_domains: Set[str] = set()
        self.known_c2_servers: Set[str] = set()
        self.ransomware_indicators: Dict[str, Dict] = {}
        
        # Behavioral tracking
        self.port_scan_tracker: DefaultDict[Tuple[str, str], Dict] = defaultdict(dict)
        self.brute_force_tracker: DefaultDict[Tuple[str, str], Dict] = defaultdict(dict)
        self.dns_tunneling_tracker: DefaultDict[str, Dict] = defaultdict(dict)
        
        # Alert tracking
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        
        # MITRE ATT&CK framework
        self.mitre_attack: Dict = {}
        self.techniques_by_id: Dict[str, Dict] = {}
        self.tactics_by_id: Dict[str, Dict] = {}
        
        # Initialize directories
        self._init_directories()
        
        # Load data
        self._load_mitre_attack()
        self._load_iocs()
        
        # Compile regex patterns
        self._compile_patterns()
    
    def _init_directories(self):
        """Initialize required directories."""
        for directory in [self.config.data_dir, self.config.ioc_dir, self.config.rules_dir]:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def _compile_patterns(self):
        """Compile regex patterns for threat detection."""
        # Common ransomware file extensions
        self.ransomware_extensions = {
            '.crypt', '.encrypted', '.locked', '.crypto', '.cryptolocker',
            '.cryptowall', '.locky', '.zepto', '.odin', '.cerber', '.xyz',
            '.zzzzz', '.aes128', '.aes256', '.rsa2048', '.wannacry', '.wncry',
            '.wcry', '.wncrypt', '.wncryptor', '.wncryptor', '.wncryptor',
            '.wncryptor', '.wncryptor', '.wncryptor', '.wncryptor', '.wncryptor'
        }
        
        # Common C2 patterns
        self.c2_patterns = [
            re.compile(r'/(c2|command|beacon|callback|panel|admin)/?', re.IGNORECASE),
            re.compile(r'(c2|command|beacon|callback)\\x[0-9a-f]{2}', re.IGNORECASE),
            re.compile(r'[a-z0-9]{16,}\.(com|net|org|info|biz|ru|cn|in|uk|de|fr|br|au|jp|pl|nl|it|es|se|ch|ca|us|me|io|xyz|pw|top|gdn|cc|tk|ml|ga|cf|gq)', re.IGNORECASE)
        ]
        
        # Common data exfiltration patterns
        self.exfil_patterns = [
            re.compile(r'(passw|pwd|ssn|credit.?card|ccnum|account.?number)', re.IGNORECASE),
            re.compile(r'[0-9]{13,16}'),  # Credit card numbers
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email addresses
            re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')  # IP addresses
        ]
    
    async def start(self):
        """Start the threat detector."""
        if self.active:
            return
            
        self.active = True
        
        # Start background tasks
        asyncio.create_task(self._ioc_updater())
        
        logger.info("Threat detector started")
    
    async def stop(self):
        """Stop the threat detector."""
        self.active = False
        logger.info("Threat detector stopped")
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for threat alerts."""
        self.alert_callbacks.append(callback)
    
    async def analyze_flow(self, flow: NetworkFlow):
        """
        Analyze a network flow for potential threats.
        
        Args:
            flow: The network flow to analyze
        """
        if not self.active:
            return
            
        try:
            # Skip whitelisted IPs
            if self._is_whitelisted(flow.src_ip) or self._is_whitelisted(flow.dst_ip):
                return
            
            # Run all enabled detectors
            if self.config.enable_c2_detection:
                await self._detect_c2(flow)
                
            if self.config.enable_ransomware_detection:
                await self._detect_ransomware(flow)
                
            if self.config.enable_insider_threat_detection:
                await self._detect_insider_threats(flow)
                
            if self.config.enable_dns_tunneling_detection and flow.protocol == Protocol.UDP and flow.dst_port == 53:
                await self._detect_dns_tunneling(flow)
                
            if self.config.enable_port_scan_detection:
                await self._detect_port_scans(flow)
            
        except Exception as e:
            logger.error(f"Error analyzing flow for threats: {e}")
    
    async def _detect_c2(self, flow: NetworkFlow):
        """Detect command and control communications."""
        # Check against known C2 servers
        if flow.dst_ip in self.known_c2_servers or flow.src_ip in self.known_c2_servers:
            self._generate_alert(
                title="Known C2 Server Communication",
                description=f"Communication with known C2 server: {flow.dst_ip}",
                threat_type=ThreatType.C2,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                confidence=0.9,
                mitre_attack_ids=["T1071"]  # Application Layer Protocol
            )
            return
        
        # Check for C2-like patterns in DNS queries
        if flow.protocol == Protocol.UDP and flow.dst_port == 53:
            # Extract domain from DNS query (simplified)
            domain = self._extract_domain_from_dns(flow)
            if domain and domain in self.known_malicious_domains:
                self._generate_alert(
                    title="Malicious Domain Resolution",
                    description=f"DNS query for known malicious domain: {domain}",
                    threat_type=ThreatType.C2,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    confidence=0.85,
                    mitre_attack_ids=["T1071.004"]  # DNS
                )
                return
            
            # Check for DGA-like domains
            if domain and is_domain_suspicious(domain):
                self._generate_alert(
                    title="Suspicious Domain Resolution",
                    description=f"DNS query for suspicious domain (possible DGA): {domain}",
                    threat_type=ThreatType.C2,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    confidence=0.7,
                    mitre_attack_ids=["T1568.002"]  # DGA
                )
    
    async def _detect_ransomware(self, flow: NetworkFlow):
        """Detect ransomware activity."""
        # Check for known ransomware indicators in the flow
        if hasattr(flow, 'payload') and flow.payload:
            payload = flow.payload.lower()
            
            # Check for ransomware extensions in file transfers
            if any(ext in payload for ext in self.ransomware_extensions):
                self._generate_alert(
                    title="Ransomware File Activity Detected",
                    description=f"Ransomware file extension detected in transfer to {flow.dst_ip}",
                    threat_type=ThreatType.RANSOMWARE,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    confidence=0.8,
                    mitre_attack_ids=["T1486"]  # Data Encrypted for Impact
                )
                return
            
            # Check for ransom notes
            ransom_keywords = [
                'ransom', 'encrypt', 'decrypt', 'bitcoin', 'wallet',
                'pay', 'payment', 'unlock', 'recover', 'your files',
                'your data', 'decryptor', 'decryption', 'private key'
            ]
            
            if any(keyword in payload for keyword in ransom_keywords):
                self._generate_alert(
                    title="Ransomware Communication Detected",
                    description=f"Ransomware-like communication pattern detected to {flow.dst_ip}",
                    threat_type=ThreatType.RANSOMWARE,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    confidence=0.75,
                    mitre_attack_ids=["T1486"]  # Data Encrypted for Impact
                )
    
    async def _detect_insider_threats(self, flow: NetworkFlow):
        """Detect potential insider threats."""
        # Check for unusual data transfers
        if flow.bytes_sent > 100 * 1024 * 1024:  # 100 MB
            self._generate_alert(
                title="Large Data Transfer Detected",
                description=f"Large outbound data transfer ({flow.bytes_sent / (1024*1024):.2f} MB) from {flow.src_ip} to {flow.dst_ip}",
                threat_type=ThreatType.INSIDER_THREAT,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                protocol=flow.protocol,
                confidence=0.7,
                mitre_attack_ids=["T1020"]  # Automated Exfiltration
            )
        
        # Check for access to sensitive resources
        if flow.dst_port in [21, 22, 3389, 1433, 3306, 5432]:  # Common management/DB ports
            self._generate_alert(
                title="Sensitive Resource Access",
                description=f"Access to sensitive service (port {flow.dst_port}) from {flow.src_ip}",
                threat_type=ThreatType.INSIDER_THREAT,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                confidence=0.6,
                mitre_attack_ids=["T1078.004"]  # Cloud Accounts
            )
    
    async def _detect_dns_tunneling(self, flow: NetworkFlow):
        """Detect potential DNS tunneling attempts."""
        if not hasattr(flow, 'payload') or not flow.payload:
            return
            
        # Extract domain from DNS query
        domain = self._extract_domain_from_dns(flow)
        if not domain:
            return
            
        # Calculate entropy of the domain
        entropy = self._calculate_entropy(domain.split('.')[0])  # Check only the subdomain
        
        # Track DNS queries for this source IP
        src_key = flow.src_ip
        if src_key not in self.dns_tunneling_tracker:
            self.dns_tunneling_tracker[src_key] = {
                'query_count': 0,
                'high_entropy_count': 0,
                'last_reset': datetime.utcnow()
            }
        
        tracker = self.dns_tunneling_tracker[src_key]
        tracker['query_count'] += 1
        
        # Check for high entropy (potential exfiltration)
        if entropy > self.config.dns_tunneling_threshold:
            tracker['high_entropy_count'] += 1
            
            # Check if we have enough evidence of DNS tunneling
            if (tracker['high_entropy_count'] / max(1, tracker['query_count'])) > 0.5:  # >50% high entropy
                self._generate_alert(
                    title="DNS Tunneling Detected",
                    description=f"High entropy DNS queries from {flow.src_ip}, possible DNS tunneling",
                    threat_type=ThreatType.DNS_TUNNELING,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    confidence=0.8,
                    mitre_attack_ids=["T1071.004"]  # DNS
                )
        
        # Reset counters periodically
        if (datetime.utcnow() - tracker['last_reset']).total_seconds() > 300:  # 5 minutes
            tracker['query_count'] = 0
            tracker['high_entropy_count'] = 0
            tracker['last_reset'] = datetime.utcnow()
    
    async def _detect_port_scans(self, flow: NetworkFlow):
        """Detect potential port scanning activity."""
        src_key = (flow.src_ip, flow.protocol)
        current_time = datetime.utcnow()
        
        # Initialize tracker for this source
        if src_key not in self.port_scan_tracker:
            self.port_scan_tracker[src_key] = {
                'ports': set(),
                'start_time': current_time,
                'last_seen': current_time
            }
        
        tracker = self.port_scan_tracker[src_key]
        tracker['ports'].add(flow.dst_port)
        tracker['last_seen'] = current_time
        
        # Check time window
        time_elapsed = (current_time - tracker['start_time']).total_seconds()
        
        # If we're still within the time window, check the count
        if time_elapsed <= 60:  # 1 minute window
            unique_ports = len(tracker['ports'])
            
            if unique_ports >= self.config.port_scan_threshold:
                self._generate_alert(
                    title="Port Scan Detected",
                    description=f"Port scan detected from {flow.src_ip}: {unique_ports} unique ports in {time_elapsed:.1f} seconds",
                    threat_type=ThreatType.PORT_SCAN,
                    source_ip=flow.src_ip,
                    protocol=flow.protocol,
                    confidence=min(0.9, 0.3 + (unique_ports / 50)),  # Cap at 0.9
                    mitre_attack_ids=["T1046"]  # Network Service Scanning
                )
                
                # Reset the tracker after alerting
                del self.port_scan_tracker[src_key]
        else:
            # Reset the tracker if the time window has passed
            del self.port_scan_tracker[src_key]
    
    def _extract_domain_from_dns(self, flow: NetworkFlow) -> Optional[str]:
        """Extract domain from DNS query."""
        if not hasattr(flow, 'payload') or not flow.payload:
            return None
            
        try:
            # This is a simplified example - real implementation would parse DNS packets
            # For now, we'll just look for common TLDs in the payload
            import re
            match = re.search(r'([a-zA-Z0-9][a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}', flow.payload)
            return match.group(0) if match else None
        except Exception:
            return None
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate the Shannon entropy of a string."""
        import math
        from collections import Counter
        
        if not data:
            return 0.0
            
        # Count character frequencies
        freq = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            p = count / data_len
            entropy -= p * math.log2(p)
            
        return entropy
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist."""
        if not ip or not self.config.whitelist_ips:
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.config.whitelist_ips:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
            
        return False
    
    def _generate_alert(
        self,
        title: str,
        description: str,
        threat_type: ThreatType,
        source_ip: str,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[Protocol] = None,
        confidence: float = 0.7,
        mitre_attack_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Generate a threat alert."""
        if confidence < self.config.min_confidence:
            return
            
        # Map threat type to alert type
        alert_type = self._map_threat_to_alert_type(threat_type)
        
        # Map MITRE ATT&CK IDs to tactics and techniques
        mitre_info = self._get_mitre_info(mitre_attack_ids or [])
        
        # Create alert
        alert = NetworkAlert(
            title=title,
            description=description,
            alert_type=alert_type,
            severity=self._determine_severity(threat_type, confidence),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            timestamp=datetime.utcnow(),
            metadata={
                'threat_type': threat_type.value,
                'confidence': confidence,
                'mitre_attack': mitre_info,
                **(metadata or {})
            }
        )
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def _map_threat_to_alert_type(self, threat_type: ThreatType) -> AlertType:
        """Map threat type to alert type."""
        if threat_type in [ThreatType.MALWARE, ThreatType.RANSOMWARE]:
            return AlertType.MALWARE
        elif threat_type in [ThreatType.C2, ThreatType.COMMAND_AND_CONTROL]:
            return AlertType.COMMAND_AND_CONTROL
        elif threat_type == ThreatType.INSIDER_THREAT:
            return AlertType.INSIDER_THREAT
        elif threat_type in [ThreatType.DATA_EXFILTRATION, ThreatType.EXFILTRATION]:
            return AlertType.DATA_EXFILTRATION
        elif threat_type in [ThreatType.PORT_SCAN, ThreatType.VULNERABILITY_SCAN]:
            return AlertType.RECONNAISSANCE
        else:
            return AlertType.SUSPICIOUS_ACTIVITY
    
    def _determine_severity(self, threat_type: ThreatType, confidence: float) -> AlertSeverity:
        """Determine alert severity based on threat type and confidence."""
        # Base severity on threat type
        if threat_type in [ThreatType.RANSOMWARE, ThreatType.C2, ThreatType.COMMAND_AND_CONTROL]:
            base_severity = AlertSeverity.HIGH
        elif threat_type in [ThreatType.MALWARE, ThreatType.INSIDER_THREAT, ThreatType.DATA_EXFILTRATION]:
            base_severity = AlertSeverity.MEDIUM
        else:
            base_severity = AlertSeverity.LOW
        
        # Adjust based on confidence
        if confidence > 0.8:
            return base_severity
        elif confidence > 0.6:
            return AlertSeverity(max(base_severity.value - 1, 1))  # Don't go below LOW
        else:
            return AlertSeverity.LOW
    
    def _load_mitre_attack(self):
        """Load MITRE ATT&CK framework data."""
        try:
            mitre_file = Path(self.config.mitre_attack_path)
            if mitre_file.exists():
                with open(mitre_file, 'r', encoding='utf-8') as f:
                    self.mitre_attack = json.load(f)
                    
                # Index techniques and tactics
                for obj in self.mitre_attack.get('objects', []):
                    if obj.get('type') == 'attack-pattern':
                        if 'external_references' in obj:
                            for ref in obj['external_references']:
                                if ref.get('source_name') == 'mitre-attack':
                                    self.techniques_by_id[ref['external_id']] = obj
                    elif obj.get('type') == 'x-mitre-tactic':
                        self.tactics_by_id[obj['x_mitre_shortname']] = obj
                        
                logger.info(f"Loaded MITRE ATT&CK framework with {len(self.techniques_by_id)} techniques and {len(self.tactics_by_id)} tactics")
            else:
                logger.warning(f"MITRE ATT&CK file not found: {mitre_file}")
                
        except Exception as e:
            logger.error(f"Error loading MITRE ATT&CK framework: {e}")
    
    def _get_mitre_info(self, technique_ids: List[str]) -> Dict[str, Any]:
        """Get MITRE ATT&CK information for the given technique IDs."""
        result = {
            'tactics': [],
            'techniques': []
        }
        
        for tech_id in technique_ids:
            technique = self.techniques_by_id.get(tech_id)
            if not technique:
                continue
                
            # Get tactic information
            tactics = []
            for phase in technique.get('kill_chain_phases', []):
                tactic = self.tactics_by_id.get(phase['phase_name'])
                if tactic:
                    tactics.append({
                        'id': tactic['id'],
                        'name': tactic['name'],
                        'description': tactic.get('description', '')
                    })
            
            # Add technique information
            result['techniques'].append({
                'id': tech_id,
                'name': technique.get('name', ''),
                'description': technique.get('description', ''),
                'url': next((ref.get('url') for ref in technique.get('external_references', [])
                           if ref.get('source_name') == 'mitre-attack'), ''),
                'tactics': tactics
            })
            
            # Add unique tactics to the result
            for tactic in tactics:
                if tactic not in result['tactics']:
                    result['tactics'].append(tactic)
        
        return result
    
    async def _ioc_updater(self):
        """Periodically update IoCs from external sources."""
        while self.active:
            try:
                logger.info("Updating IoCs...")
                await self._update_iocs()
                logger.info(f"Updated {len(self.iocs)} IoCs")
                
            except Exception as e:
                logger.error(f"Error updating IoCs: {e}")
                
            # Wait before next update
            await asyncio.sleep(self.config.ioc_update_interval)
    
    async def _update_iocs(self):
        """Update indicators of compromise from various sources."""
        # This is a placeholder for actual IoC update logic
        # In a real implementation, this would fetch from threat feeds, MISP, etc.
        
        # Example: Load from files in the IoC directory
        for ioc_file in Path(self.config.ioc_dir).glob('*.json'):
            try:
                with open(ioc_file, 'r') as f:
                    ioc_data = json.load(f)
                    
                if isinstance(ioc_data, list):
                    for item in ioc_data:
                        self._process_ioc(item)
                else:
                    self._process_ioc(ioc_data)
                    
            except Exception as e:
                logger.error(f"Error processing IoC file {ioc_file}: {e}")
    
    def _process_ioc(self, ioc_data: Dict[str, Any]):
        """Process a single IoC."""
        try:
            ioc_type = ioc_data.get('type', '').lower()
            value = ioc_data.get('value', '').strip()
            
            if not value:
                return
                
            # Create a unique key for this IoC
            ioc_key = f"{ioc_type}:{value}"
            
            # Skip if we already have this IoC
            if ioc_key in self.iocs:
                return
                
            # Parse threat type
            threat_type = ThreatType.UNKNOWN
            if 'threat_type' in ioc_data:
                try:
                    threat_type = ThreatType(ioc_data['threat_type'].lower())
                except ValueError:
                    pass
            
            # Create IoC object
            now = datetime.utcnow()
            ioc = IoC(
                ioc_type=ioc_type,
                value=value,
                threat_type=threat_type,
                confidence=float(ioc_data.get('confidence', 0.7)),
                first_seen=now,
                last_seen=now,
                description=ioc_data.get('description', ''),
                tags=ioc_data.get('tags', []),
                mitre_attack_ids=ioc_data.get('mitre_attack_ids', []),
                metadata=ioc_data.get('metadata', {})
            )
            
            # Add to appropriate collections
            self.iocs[ioc_key] = ioc
            
            if ioc_type == 'ip':
                if threat_type in [ThreatType.C2, ThreatType.MALWARE, ThreatType.RANSOMWARE]:
                    self.known_malicious_ips.add(value)
                    if threat_type == ThreatType.C2:
                        self.known_c2_servers.add(value)
            elif ioc_type == 'domain':
                if threat_type in [ThreatType.C2, ThreatType.MALWARE, ThreatType.RANSOMWARE]:
                    self.known_malicious_domains.add(value.lower())
                    if threat_type == ThreatType.C2:
                        self.known_c2_servers.add(value.lower())
            
        except Exception as e:
            logger.error(f"Error processing IoC {ioc_data.get('value', 'unknown')}: {e}")
    
    def _load_iocs(self):
        """Load IoCs from disk."""
        # This would load from persistent storage in a real implementation
        pass
        
    def _save_iocs(self):
        """Save IoCs to disk."""
        # This would save to persistent storage in a real implementation
        pass
