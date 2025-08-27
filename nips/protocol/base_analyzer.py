"""
Base Protocol Analyzer for NIPS
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union
import re
import ipaddress

class Protocol(Enum):
    """Supported network protocols."""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    SSH = "ssh"
    TELNET = "telnet"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"

class ProtocolViolationType(Enum):
    """Types of protocol violations."""
    MALFORMED_PACKET = "malformed_packet"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    POLICY_VIOLATION = "policy_violation"
    INVALID_STATE = "invalid_state"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EVASION_ATTEMPT = "evasion_attempt"

@dataclass
class ProtocolViolation:
    """Represents a protocol violation."""
    protocol: Protocol
    violation_type: ProtocolViolationType
    description: str
    severity: int  # 1-5, with 5 being most severe
    packet_data: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'protocol': self.protocol.value,
            'violation_type': self.violation_type.value,
            'description': self.description,
            'severity': self.severity,
            'packet_data': self.packet_data.hex() if self.packet_data else "",
            'metadata': self.metadata
        }

class ProtocolAnalyzer(ABC):
    """Base class for protocol analyzers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the protocol analyzer."""
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.violations: List[ProtocolViolation] = []
        self.state: Dict[str, Any] = {}
    
    @property
    @abstractmethod
    def protocol(self) -> Protocol:
        """Get the protocol this analyzer handles."""
        pass
    
    @abstractmethod
    def analyze(self, packet: bytes, metadata: Dict[str, Any]) -> List[ProtocolViolation]:
        """
        Analyze a packet for protocol violations.
        
        Args:
            packet: The raw packet data
            metadata: Additional metadata about the packet
            
        Returns:
            List of protocol violations found
        """
        pass
    
    def reset(self):
        """Reset the analyzer's state."""
        self.violations.clear()
        self.state.clear()
    
    def _add_violation(self, 
                      violation_type: ProtocolViolationType,
                      description: str,
                      severity: int,
                      packet_data: bytes = b"",
                      metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a protocol violation.
        
        Args:
            violation_type: Type of violation
            description: Description of the violation
            severity: Severity level (1-5)
            packet_data: The packet data that caused the violation
            metadata: Additional metadata about the violation
        """
        violation = ProtocolViolation(
            protocol=self.protocol,
            violation_type=violation_type,
            description=description,
            severity=min(max(1, severity), 5),  # Ensure severity is between 1 and 5
            packet_data=packet_data,
            metadata=metadata or {}
        )
        self.violations.append(violation)
    
    def get_violations(self) -> List[ProtocolViolation]:
        """Get all violations found by this analyzer."""
        return self.violations.copy()

class ProtocolManager:
    """Manages protocol analyzers and dispatches packets to them."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the protocol manager."""
        self.config = config or {}
        self.analyzers: Dict[Protocol, ProtocolAnalyzer] = {}
        self._initialize_analyzers()
    
    def _initialize_analyzers(self):
        """Initialize protocol analyzers based on configuration."""
        analyzers_config = self.config.get('analyzers', {})
        
        # Import analyzers dynamically based on configuration
        try:
            # HTTP/HTTPS analyzer
            if analyzers_config.get('http', {}).get('enabled', True):
                from .http_analyzer import HTTPAnalyzer
                self.analyzers[Protocol.HTTP] = HTTPAnalyzer(analyzers_config.get('http', {}))
                self.analyzers[Protocol.HTTPS] = self.analyzers[Protocol.HTTP]  # Same analyzer for both
            
            # DNS analyzer
            if analyzers_config.get('dns', {}).get('enabled', True):
                from .dns_analyzer import DNSAnalyzer
                self.analyzers[Protocol.DNS] = DNSAnalyzer(analyzers_config.get('dns', {}))
            
            # FTP analyzer
            if analyzers_config.get('ftp', {}).get('enabled', True):
                from .ftp_analyzer import FTPAnalyzer
                self.analyzers[Protocol.FTP] = FTPAnalyzer(analyzers_config.get('ftp', {}))
            
            # SMTP analyzer
            if analyzers_config.get('smtp', {}).get('enabled', True):
                from .smtp_analyzer import SMTPAnalyzer
                self.analyzers[Protocol.SMTP] = SMTPAnalyzer(analyzers_config.get('smtp', {}))
            
        except ImportError as e:
            print(f"Warning: Failed to load protocol analyzer: {e}")
    
    def analyze_packet(self, 
                      packet: bytes, 
                      protocol: Protocol, 
                      metadata: Optional[Dict[str, Any]] = None) -> List[ProtocolViolation]:
        """
        Analyze a packet for protocol violations.
        
        Args:
            packet: The raw packet data
            protocol: The protocol of the packet
            metadata: Additional metadata about the packet
            
        Returns:
            List of protocol violations found
        """
        if protocol not in self.analyzers or not self.analyzers[protocol].enabled:
            return []
        
        try:
            return self.analyzers[protocol].analyze(packet, metadata or {})
        except Exception as e:
            # Log the error but don't crash
            print(f"Error in {protocol.value} analyzer: {e}")
            return []
    
    def get_analyzer(self, protocol: Protocol) -> Optional[ProtocolAnalyzer]:
        """Get a protocol analyzer by protocol."""
        return self.analyzers.get(protocol)
    
    def reset_analyzers(self):
        """Reset all protocol analyzers."""
        for analyzer in self.analyzers.values():
            analyzer.reset()
    
    def get_all_violations(self) -> Dict[Protocol, List[ProtocolViolation]]:
        """Get all violations from all analyzers."""
        return {
            protocol: analyzer.get_violations()
            for protocol, analyzer in self.analyzers.items()
        }
