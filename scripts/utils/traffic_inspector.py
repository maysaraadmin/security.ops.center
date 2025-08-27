"""
Traffic Inspector for NIPS

This module implements deep packet inspection and traffic analysis capabilities
for the Network Intrusion Prevention System.
"""

import re
import logging
import binascii
import zlib
import base64
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Any, Union, DefaultDict, Pattern
from dataclasses import dataclass, field
from collections import defaultdict, deque
import ipaddress
import datetime
import struct

logger = logging.getLogger('nips.traffic_inspector')

@dataclass
class TrafficStats:
    """Traffic statistics for a flow."""
    # Basic counters
    packet_count: int = 0
    byte_count: int = 0
    
    # Protocol distribution
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Port distribution
    src_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    dst_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    # Packet size statistics
    packet_sizes: List[int] = field(default_factory=list)
    
    # Flow duration
    start_time: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    last_seen: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    
    # Connection states
    connection_states: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Flag distribution
    tcp_flags: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Payload analysis
    entropy_values: List[float] = field(default_factory=list)
    
    def update(self, packet: Dict[str, Any]):
        """Update statistics with a new packet."""
        self.packet_count += 1
        self.byte_count += packet.get('length', 0)
        self.last_seen = datetime.datetime.now().timestamp()
        
        # Update protocol distribution
        protocol = packet.get('protocol', 'unknown').lower()
        self.protocol_counts[protocol] += 1
        
        # Update port distributions
        src_port = packet.get('src_port')
        if src_port is not None:
            self.src_port_counts[src_port] += 1
            
        dst_port = packet.get('dst_port')
        if dst_port is not None:
            self.dst_port_counts[dst_port] += 1
        
        # Update packet sizes
        self.packet_sizes.append(packet.get('length', 0))
        
        # Update TCP flags if available
        if 'tcp_flags' in packet:
            for flag, value in packet['tcp_flags'].items():
                if value:
                    self.tcp_flags[flag] += 1
        
        # Update connection states
        if 'tcp_flags' in packet:
            flags = packet['tcp_flags']
            if flags.get('syn') and not flags.get('ack'):
                self.connection_states['syn'] += 1
            elif flags.get('syn') and flags.get('ack'):
                self.connection_states['syn_ack'] += 1
            elif flags.get('fin'):
                self.connection_states['fin'] += 1
            elif flags.get('rst'):
                self.connection_states['rst'] += 1
        
        # Calculate payload entropy if available
        if 'payload' in packet and packet['payload']:
            self.entropy_values.append(self._calculate_entropy(packet['payload']))
    
    def get_duration(self) -> float:
        """Get the duration of the traffic flow in seconds."""
        return self.last_seen - self.start_time
    
    def get_avg_packet_size(self) -> float:
        """Get the average packet size."""
        if not self.packet_sizes:
            return 0.0
        return sum(self.packet_sizes) / len(self.packet_sizes)
    
    def get_avg_entropy(self) -> float:
        """Get the average entropy of the payload."""
        if not self.entropy_values:
            return 0.0
        return sum(self.entropy_values) / len(self.entropy_values)
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate the Shannon entropy of the given data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x and math.log(p_x, 2))
        
        return entropy

class TrafficInspector:
    """Performs deep packet inspection and traffic analysis."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the traffic inspector.
        
        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        
        # Traffic statistics
        self.stats: Dict[str, TrafficStats] = {}
        
        # Known malicious indicators
        self.known_malicious_ips: Set[str] = set()
        self.known_malicious_domains: Set[str] = set()
        self.known_malicious_hashes: Set[str] = set()
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex_encoded': re.compile(r'[0-9a-fA-F]{20,}'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'url': re.compile(r'https?://[^\s/$.?#].[^\s]*'),
            'executable_magic': [
                (b'MZ', 'Windows PE'),
                (b'\x7fELF', 'ELF'),
                (b'#!', 'Script'),
                (b'\x4D\x5A', 'DOS Executable'),
                (b'\x5A\x4D', 'DOS Executable (reversed)')
            ],
            'suspicious_strings': [
                'cmd.exe', 'powershell', 'wscript', 'cscript', 'regsvr32',
                'rundll32', 'mshta', 'certutil', 'bitsadmin', 'wmic',
                'schtasks', 'psexec', 'net use', 'net user', 'net localgroup',
                'net group', 'net1 user', 'net1 localgroup', 'net1 group',
                'whoami', 'ipconfig', 'systeminfo', 'tasklist', 'netstat',
                'nslookup', 'tracert', 'ping', 'nmap', 'nc ', 'netcat',
                'ssh ', 'telnet', 'ftp ', 'tftp ', 'wget', 'curl', 'certutil',
                'vssadmin', 'bcdedit', 'wbadmin', 'wmic', 'wscript.shell',
                'shell.application', 'wshshell', 'scripting.filesystemobject',
                'adodb.stream', 'xmlhttp', 'winmgmts:', 'win32_process',
                'win32_service', 'win32_share', 'win32_useraccount',
                'win32_group', 'win32_logicaldisk', 'win32_networkadapter',
                'win32_networkadapterconfiguration', 'win32_nteventlog',
                'win32_operatingsystem', 'win32_processstartup',
                'win32_share', 'win32_systemenclosure', 'win32_systemdriver',
                'win32_systemservices', 'win32_timezone', 'win32_useraccount',
                'win32_wmiset', 'winrm', 'winrs', 'wmic', 'wscript.shell',
                'wshshell', 'xmlhttp', 'xcopy', 'xcopy32', 'xcopy64',
                'xcopy /e /i /h /y', 'xcopy /e /i /h /y /c', 'xcopy /e /i /h /y /q',
                'xcopy /e /i /h /y /c /q /f /r /d /y /z /j /k /l /s /exclude:\\?\ %TEMP%\\*.* %TEMP%\\*.* %TEMP%\\',
                'xcopy /e /i /h /y /c /q /f /r /d /y /z /j /k /l /s /exclude:\\?\ %TEMP%\\*.* %TEMP%\\*.* %TEMP%\\*.*',
            ]
        }
        
        # File type signatures
        self.file_signatures = {
            # Executables
            b'MZ': 'Windows PE',
            b'\x7fELF': 'ELF',
            b'#!': 'Script',
            b'\x4D\x5A': 'DOS Executable',
            # Documents
            b'\x50\x4B\x03\x04': 'ZIP/Office Document',
            b'\x50\x4B\x05\x06': 'ZIP Archive',
            b'\x50\x4B\x07\x08': 'ZIP Archive',
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'Microsoft Office Document',
            b'%PDF-': 'PDF Document',
            # Archives
            b'\x1F\x8B\x08': 'GZIP',
            b'\x42\x5A\x68': 'BZIP2',
            b'\x52\x61\x72\x21\x1A\x07\x00': 'RAR',
            b'\x37\x7A\xBC\xAF\x27\x1C': '7z',
            # Images
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'\x49\x49\x2A\x00': 'TIFF',
            b'\x4D\x4D\x00\x2A': 'TIFF',
            b'BM': 'BMP',
            # Audio/Video
            b'ID3': 'MP3',
            b'\x00\x00\x00 ftypisom': 'MP4',
            b'\x00\x00\x00 ftypqt': 'QuickTime',
            b'\x1A\x45\xDF\xA3': 'WebM/Matroska',
            b'RIFF....WEBP': 'WebP',
            b'RIFF....WAVE': 'WAV',
            b'OggS': 'Ogg',
            # Other
            b'\xEF\xBB\xBF': 'UTF-8 with BOM',
            b'\xFF\xFE': 'UTF-16LE',
            b'\xFE\xFF': 'UTF-16BE',
            b'\x00\x00\xFE\xFF': 'UTF-32BE',
            b'\xFF\xFE\x00\x00': 'UTF-32LE'
        }
        
        # Initialize with known malicious indicators if provided in config
        if 'known_malicious_ips' in self.config:
            self.known_malicious_ips.update(self.config['known_malicious_ips'])
        if 'known_malicious_domains' in self.config:
            self.known_malicious_domains.update(self.config['known_malicious_domains'])
        if 'known_malicious_hashes' in self.config:
            self.known_malicious_hashes.update(self.config['known_malicious_hashes'])
        
        logger.info("Traffic inspector initialized")
    
    def inspect_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Inspect a network packet for suspicious content.
        
        Args:
            packet: The packet to inspect
            
        Returns:
            List of findings/detections
        """
        findings = []
        
        # Update traffic statistics
        flow_key = self._get_flow_key(packet)
        if flow_key not in self.stats:
            self.stats[flow_key] = TrafficStats()
        self.stats[flow_key].update(packet)
        
        # Check for known malicious indicators
        findings.extend(self._check_malicious_indicators(packet))
        
        # Check for suspicious patterns in payload
        if 'payload' in packet and packet['payload']:
            findings.extend(self._analyze_payload(packet['payload'], packet))
        
        # Check for protocol anomalies
        findings.extend(self._check_protocol_anomalies(packet))
        
        # Check for data exfiltration attempts
        findings.extend(self._check_data_exfiltration(packet))
        
        # Check for command and control (C2) communication patterns
        findings.extend(self._check_c2_communication(packet))
        
        return findings
    
    def _get_flow_key(self, packet: Dict[str, Any]) -> str:
        """Generate a flow key for the given packet."""
        return (
            f"{packet.get('src_ip')}:{packet.get('src_port')}-{packet.get('dst_ip')}:"
            f"{packet.get('dst_port')}-{packet.get('protocol', 'unknown')}"
        )
    
    def _check_malicious_indicators(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for known malicious indicators in the packet."""
        findings = []
        
        # Check source and destination IPs against known malicious IPs
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if src_ip in self.known_malicious_ips:
            findings.append({
                'type': 'MALICIOUS_IP',
                'severity': 'high',
                'message': f'Source IP {src_ip} is known to be malicious',
                'details': {
                    'ip': src_ip,
                    'direction': 'source',
                    'packet': packet
                }
            })
        
        if dst_ip in self.known_malicious_ips:
            findings.append({
                'type': 'MALICIOUS_IP',
                'severity': 'high',
                'message': f'Destination IP {dst_ip} is known to be malicious',
                'details': {
                    'ip': dst_ip,
                    'direction': 'destination',
                    'packet': packet
                }
            })
        
        # Check for known malicious domains in DNS queries or HTTP headers
        if 'dns_query' in packet and packet['dns_query']:
            query = packet['dns_query'].lower()
            for domain in self.known_malicious_domains:
                if domain.lower() in query:
                    findings.append({
                        'type': 'MALICIOUS_DOMAIN',
                        'severity': 'high',
                        'message': f'DNS query for known malicious domain: {query}',
                        'details': {
                            'domain': query,
                            'malicious_domain': domain,
                            'packet': packet
                        }
                    })
                    break
        
        return findings
    
    def _analyze_payload(self, payload: bytes, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet payload for suspicious content."""
        findings = []
        
        if not payload:
            return findings
        
        # Check for file signatures
        file_type = self._detect_file_type(payload)
        if file_type and file_type not in ['Text', 'Unknown']:
            findings.append({
                'type': 'FILE_DETECTED',
                'severity': 'info',
                'message': f'Detected file type: {file_type}',
                'details': {
                    'file_type': file_type,
                    'packet': packet
                }
            })
        
        # Check for executable content in unexpected places
        if file_type in ['Windows PE', 'ELF', 'DOS Executable'] and \
           packet.get('protocol') not in ['http', 'https', 'ftp', 'smtp']:
            findings.append({
                'type': 'EXECUTABLE_DETECTED',
                'severity': 'high',
                'message': f'Executable file detected in {packet.get("protocol", "unknown")} traffic',
                'details': {
                    'file_type': file_type,
                    'packet': packet
                }
            })
        
        # Check for suspicious strings
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            for suspicious in self.suspicious_patterns['suspicious_strings']:
                if suspicious.lower() in payload_str.lower():
                    # Get context around the match
                    idx = payload_str.lower().find(suspicious.lower())
                    start = max(0, idx - 20)
                    end = min(len(payload_str), idx + len(suspicious) + 20)
                    context = payload_str[start:end].replace('\n', ' ').replace('\r', ' ')
                    
                    findings.append({
                        'type': 'SUSPICIOUS_STRING',
                        'severity': 'medium',
                        'message': f'Suspicious string found: {suspicious}',
                        'details': {
                            'string': suspicious,
                            'context': context,
                            'packet': packet
                        }
                    })
        except UnicodeDecodeError:
            pass
        
        # Check for base64 encoded data
        if len(payload) > 20:  # Minimum length for meaningful base64
            try:
                # Try to decode as base64
                decoded = base64.b64decode(payload, validate=True)
                if len(decoded) > 0:
                    # If it decodes successfully, it might be worth investigating
                    findings.append({
                        'type': 'BASE64_ENCODED',
                        'severity': 'low',
                        'message': 'Base64 encoded data detected',
                        'details': {
                            'original_length': len(payload),
                            'decoded_length': len(decoded),
                            'packet': packet
                        }
                    })
            except (binascii.Error, ValueError):
                pass
        
        # Check for high entropy (possible encrypted or compressed data)
        entropy = self._calculate_entropy(payload)
        if entropy > 7.5:  # High entropy threshold
            findings.append({
                'type': 'HIGH_ENTROPY',
                'severity': 'medium',
                'message': f'High entropy data detected (entropy: {entropy:.2f})',
                'details': {
                    'entropy': entropy,
                    'packet': packet
                }
            })
        
        return findings
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type based on magic numbers."""
        for signature, file_type in self.file_signatures.items():
            if data.startswith(signature):
                return file_type
        
        # Check for text content
        try:
            text = data.decode('utf-8', errors='strict')
            if any(c.isprintable() or c in '\t\n\r' for c in text):
                return 'Text'
        except UnicodeDecodeError:
            pass
        
        return 'Unknown'
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate the Shannon entropy of the given data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x and math.log(p_x, 2))
        
        return entropy
    
    def _check_protocol_anomalies(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for protocol anomalies in the packet."""
        findings = []
        protocol = packet.get('protocol', '').lower()
        
        if protocol == 'tcp':
            # Check for TCP anomalies
            if 'tcp_flags' in packet:
                flags = packet['tcp_flags']
                
                # Check for NULL scan
                if all(not flag for flag in flags.values()):
                    findings.append({
                        'type': 'TCP_NULL_SCAN',
                        'severity': 'high',
                        'message': 'TCP NULL scan detected',
                        'details': {'packet': packet}
                    })
                
                # Check for XMAS scan
                if flags.get('fin') and flags.get('urg') and flags.get('psh'):
                    findings.append({
                        'type': 'TCP_XMAS_SCAN',
                        'severity': 'high',
                        'message': 'TCP XMAS scan detected',
                        'details': {'packet': packet}
                    })
                
                # Check for FIN scan
                if flags.get('fin') and not any(flags.get(f) for f in ['syn', 'rst', 'ack']):
                    findings.append({
                        'type': 'TCP_FIN_SCAN',
                        'severity': 'high',
                        'message': 'TCP FIN scan detected',
                        'details': {'packet': packet}
                    })
        
        elif protocol == 'dns':
            # Check for DNS anomalies
            if 'dns_query' in packet and packet['dns_query']:
                query = packet['dns_query']
                
                # Check for long domain names (possible tunneling)
                if len(query) > 253:  # Max domain name length is 253 chars
                    findings.append({
                        'type': 'DNS_LONG_QUERY',
                        'severity': 'medium',
                        'message': f'Excessively long DNS query: {len(query)} characters',
                        'details': {
                            'query': query,
                            'length': len(query),
                            'packet': packet
                        }
                    })
                
                # Check for suspicious domain names
                if any(c.isupper() for c in query):
                    findings.append({
                        'type': 'DNS_SUSPICIOUS_QUERY',
                        'severity': 'low',
                        'message': 'DNS query contains uppercase letters (possible obfuscation)',
                        'details': {
                            'query': query,
                            'packet': packet
                        }
                    })
        
        return findings
    
    def _check_data_exfiltration(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential data exfiltration attempts."""
        findings = []
        
        # Check for large outbound transfers to external IPs
        if 'payload' in packet and packet['payload']:
            payload_size = len(packet['payload'])
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            # Skip if we don't have IP information
            if not src_ip or not dst_ip:
                return findings
            
            # Check if source is internal and destination is external
            if self._is_internal_ip(src_ip) and not self._is_internal_ip(dst_ip):
                # Large outbound transfer
                if payload_size > 1024 * 1024:  # 1 MB
                    findings.append({
                        'type': 'LARGE_OUTBOUND_TRANSFER',
                        'severity': 'high',
                        'message': f'Large outbound data transfer detected: {payload_size} bytes',
                        'details': {
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'size': payload_size,
                            'protocol': packet.get('protocol'),
                            'packet': packet
                        }
                    })
                
                # Check for common data exfiltration techniques
                if packet.get('protocol') == 'dns':
                    # DNS tunneling/exfiltration
                    if 'dns_query' in packet and packet['dns_query']:
                        query = packet['dns_query']
                        
                        # Check for base64 or hex encoded data in subdomains
                        if any(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in query):
                            findings.append({
                                'type': 'DNS_EXFILTRATION',
                                'severity': 'high',
                                'message': 'Possible DNS exfiltration attempt detected',
                                'details': {
                                    'query': query,
                                    'packet': packet
                                }
                            })
        
        return findings
    
    def _check_c2_communication(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for command and control (C2) communication patterns."""
        findings = []
        
        # Check for beaconing behavior (periodic communication)
        flow_key = self._get_flow_key(packet)
        if flow_key in self.stats:
            stats = self.stats[flow_key]
            
            # Calculate packets per second
            duration = stats.get_duration()
            if duration > 0:
                pps = stats.packet_count / duration
                
                # Low and consistent packet rate might indicate beaconing
                if 0.1 <= pps <= 2.0:  # Between 1 packet every 10 seconds and 2 packets per second
                    findings.append({
                        'type': 'POSSIBLE_BEACONING',
                        'severity': 'medium',
                        'message': f'Possible beaconing behavior detected: {pps:.2f} packets/second',
                        'details': {
                            'packets_per_second': pps,
                            'duration': duration,
                            'packet_count': stats.packet_count,
                            'flow': flow_key,
                            'packet': packet
                        }
                    })
        
        # Check for HTTP C2 patterns
        if packet.get('protocol') == 'http' and 'http_headers' in packet:
            headers = packet['http_headers']
            
            # Check for common C2 user agents
            if 'user-agent' in headers:
                ua = headers['user-agent'].lower()
                c2_indicators = [
                    'python-requests', 'curl', 'wget', 'powershell',
                    'winhttp', 'mozilla/4.0', 'msie 6.0', 'msie 7.0',
                    'msie 8.0', 'msie 9.0', 'msie 10.0', 'msie 11.0',
                    'trident/4.0', 'trident/5.0', 'trident/6.0', 'trident/7.0'
                ]
                
                if any(indicator in ua for indicator in c2_indicators):
                    findings.append({
                        'type': 'SUSPICIOUS_USER_AGENT',
                        'severity': 'medium',
                        'message': f'Suspicious User-Agent detected: {headers["user-agent"]}',
                        'details': {
                            'user_agent': headers['user-agent'],
                            'packet': packet
                        }
                    })
            
            # Check for unusual HTTP methods
            if 'method' in packet and packet['method'] not in ['GET', 'POST', 'HEAD', 'OPTIONS']:
                findings.append({
                    'type': 'UNUSUAL_HTTP_METHOD',
                    'severity': 'low',
                    'message': f'Unusual HTTP method: {packet["method"]}',
                    'details': {
                        'method': packet['method'],
                        'packet': packet
                    }
                })
            
            # Check for unusual HTTP response codes
            if 'status_code' in packet and packet['status_code'] >= 400:
                findings.append({
                    'type': 'HTTP_ERROR_RESPONSE',
                    'severity': 'low',
                    'message': f'HTTP error response: {packet["status_code"]}',
                    'details': {
                        'status_code': packet['status_code'],
                        'packet': packet
                    }
                })
        
        return findings
    
    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if an IP address is in a private range."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
