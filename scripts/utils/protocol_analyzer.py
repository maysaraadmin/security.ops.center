"""
Protocol Analyzer for NIPS

This module implements protocol analysis for detecting protocol-level anomalies
and violations in network traffic.
"""

import re
import logging
import ipaddress
from typing import Dict, List, Optional, Set, Tuple, Any, Union, DefaultDict
from dataclasses import dataclass, field
from collections import defaultdict
import datetime

logger = logging.getLogger('nips.protocol_analyzer')

@dataclass
class ProtocolState:
    """Tracks the state of a protocol session."""
    # Basic connection info
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    
    # Timestamps
    start_time: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    last_seen: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    
    # Protocol-specific state
    tcp_state: Optional[str] = None  # For TCP state tracking
    tcp_flags: Set[str] = field(default_factory=set)  # Observed TCP flags
    tcp_sequence: Optional[int] = None  # TCP sequence number tracking
    tcp_ack: Optional[int] = None  # TCP ACK number tracking
    
    # HTTP state
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_version: Optional[str] = None
    http_status_code: Optional[int] = None
    
    # DNS state
    dns_queries: List[Dict[str, Any]] = field(default_factory=list)
    dns_answers: List[Dict[str, Any]] = field(default_factory=list)
    
    # Protocol violations
    violations: List[Dict[str, Any]] = field(default_factory=list)
    
    def update_timestamp(self):
        """Update the last seen timestamp."""
        self.last_seen = datetime.datetime.now().timestamp()
    
    def add_violation(self, rule_id: str, message: str, severity: str = 'medium',
                     details: Optional[Dict[str, Any]] = None):
        """Add a protocol violation."""
        self.violations.append({
            'timestamp': datetime.datetime.now().timestamp(),
            'rule_id': rule_id,
            'message': message,
            'severity': severity,
            'details': details or {}
        })

class ProtocolAnalyzer:
    """Analyzes network protocols for anomalies and violations."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the protocol analyzer.
        
        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        self.sessions: Dict[str, ProtocolState] = {}
        self.session_timeout = 3600  # 1 hour session timeout by default
        
        # Protocol-specific configuration
        self.http_config = {
            'max_uri_length': 4096,
            'max_header_size': 8192,
            'max_headers': 100,
            'allowed_methods': {'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'},
            'allowed_versions': {'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'}
        }
        
        self.dns_config = {
            'max_query_length': 512,
            'max_response_length': 4096,
            'max_labels': 127,
            'max_label_length': 63
        }
        
        self.tcp_config = {
            'max_window_size': 65535,
            'max_syn_retries': 3,
            'syn_timeout': 30  # seconds
        }
        
        # Update config with any user-provided values
        if 'http' in self.config:
            self.http_config.update(self.config['http'])
        if 'dns' in self.config:
            self.dns_config.update(self.config['dns'])
        if 'tcp' in self.config:
            self.tcp_config.update(self.config['tcp'])
        
        # Compile regex patterns
        self.http_request_pattern = re.compile(
            r'^(?P<method>[A-Z]+)\s+(?P<uri>[^\s]+)\s+HTTP/(?P<version>1\.[01]|2)$',
            re.IGNORECASE
        )
        self.http_response_pattern = re.compile(
            r'^HTTP/(?P<version>1\.[01]|2)\s+(?P<status_code>\d{3})\s*(?P<reason>.*)?$',
            re.IGNORECASE
        )
        self.http_header_pattern = re.compile(
            r'^(?P<name>[^:\s]+)\s*:\s*(?P<value>.*?)\s*$',
            re.IGNORECASE
        )
        
        logger.info("Protocol analyzer initialized")
    
    def get_session_key(self, packet: Dict[str, Any]) -> str:
        """Generate a unique session key for a packet."""
        return (
            f"{packet.get('src_ip')}:{packet.get('src_port')}-{packet.get('dst_ip')}:"
            f"{packet.get('dst_port')}-{packet.get('protocol', 'unknown')}"
        )
    
    def get_or_create_session(self, packet: Dict[str, Any]) -> ProtocolState:
        """Get or create a protocol session for the given packet."""
        session_key = self.get_session_key(packet)
        
        # Clean up old sessions
        self._cleanup_sessions()
        
        if session_key not in self.sessions:
            self.sessions[session_key] = ProtocolState(
                src_ip=packet.get('src_ip'),
                src_port=packet.get('src_port'),
                dst_ip=packet.get('dst_ip'),
                dst_port=packet.get('dst_port'),
                protocol=packet.get('protocol', 'unknown')
            )
        else:
            self.sessions[session_key].update_timestamp()
        
        return self.sessions[session_key]
    
    def _cleanup_sessions(self):
        """Remove stale sessions."""
        current_time = datetime.datetime.now().timestamp()
        stale_keys = [
            key for key, session in self.sessions.items()
            if current_time - session.last_seen > self.session_timeout
        ]
        
        for key in stale_keys:
            del self.sessions[key]
    
    def analyze_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a network packet for protocol violations.
        
        Args:
            packet: The packet to analyze
            
        Returns:
            List of detected violations
        """
        if not packet or 'protocol' not in packet:
            return []
        
        protocol = packet.get('protocol', '').lower()
        session = self.get_or_create_session(packet)
        
        # Clear previous violations for this packet
        session.violations = []
        
        # Protocol-specific analysis
        if protocol == 'tcp':
            self._analyze_tcp(packet, session)
        elif protocol == 'http':
            self._analyze_http(packet, session)
        elif protocol == 'dns':
            self._analyze_dns(packet, session)
        
        return session.violations
    
    def _analyze_tcp(self, packet: Dict[str, Any], session: ProtocolState):
        """Analyze TCP protocol violations."""
        tcp_flags = packet.get('tcp_flags', {})
        
        # Track TCP state
        if tcp_flags.get('syn') and not tcp_flags.get('ack'):
            # SYN packet
            if session.tcp_state != 'ESTABLISHED':
                session.tcp_state = 'SYN_SENT'
            else:
                session.add_violation(
                    'TCP_INVALID_STATE',
                    'SYN packet in established connection',
                    'high',
                    {'packet': packet}
                )
        
        # Check for TCP flags anomalies
        if tcp_flags.get('syn') and tcp_flags.get('fin'):
            session.add_violation(
                'TCP_SYN_FIN',
                'SYN and FIN flags set in the same packet',
                'high',
                {'packet': packet}
            )
        
        if tcp_flags.get('fin') and not session.tcp_state == 'ESTABLISHED':
            session.add_violation(
                'TCP_INVALID_FIN',
                'FIN packet in non-established connection',
                'medium',
                {'packet': packet, 'state': session.tcp_state}
            )
        
        # Check for TCP window size anomalies
        window_size = packet.get('tcp_window', 0)
        if window_size > self.tcp_config['max_window_size']:
            session.add_violation(
                'TCP_WINDOW_SIZE',
                f'Excessive TCP window size: {window_size}',
                'low',
                {'window_size': window_size, 'max_allowed': self.tcp_config['max_window_size']}
            )
        
        # Check for TCP sequence number anomalies
        seq_num = packet.get('tcp_seq')
        if seq_num is not None and session.tcp_sequence is not None:
            if seq_num < session.tcp_sequence:
                session.add_violation(
                    'TCP_SEQUENCE',
                    'TCP sequence number moved backward',
                    'high',
                    {'current_seq': seq_num, 'previous_seq': session.tcp_sequence}
                )
            session.tcp_sequence = seq_num
    
    def _analyze_http(self, packet: Dict[str, Any], session: ProtocolState):
        """Analyze HTTP protocol violations."""
        payload = packet.get('payload', b'').decode('utf-8', errors='ignore')
        
        # Check if this is an HTTP request or response
        if not session.http_method and 'HTTP/' not in payload:
            # Not an HTTP packet
            return
        
        lines = payload.split('\r\n')
        
        # Parse request/response line
        if not session.http_method and not session.http_status_code:
            first_line = lines[0].strip()
            
            # Check for HTTP request
            match = self.http_request_pattern.match(first_line)
            if match:
                session.http_method = match.group('method')
                session.http_uri = match.group('uri')
                session.http_version = f"HTTP/{match.group('version')}"
                
                # Check HTTP method
                if session.http_method not in self.http_config['allowed_methods']:
                    session.add_violation(
                        'HTTP_METHOD',
                        f'Unusual HTTP method: {session.http_method}',
                        'medium',
                        {'method': session.http_method}
                    )
                
                # Check URI length
                if len(session.http_uri) > self.http_config['max_uri_length']:
                    session.add_violation(
                        'HTTP_URI_LENGTH',
                        f'Excessive URI length: {len(session.http_uri)}',
                        'low',
                        {'uri_length': len(session.http_uri), 'max_allowed': self.http_config['max_uri_length']}
                    )
                
                # Check for path traversal attempts
                if any(seq in session.http_uri for seq in ['../', '..\\', '%2e%2e%2f', '%2e%2e/']):
                    session.add_violation(
                        'HTTP_PATH_TRAVERSAL',
                        'Possible path traversal attempt in URI',
                        'high',
                        {'uri': session.http_uri}
                    )
                
                # Check for SQL injection patterns
                sql_patterns = [
                    r'(?i)(?:union\s+select|select\s+\*\s+from|insert\s+into|delete\s+from|update\s+\w+\s+set)',
                    r'(?i)(?:drop\s+table|truncate\s+table|exec\s+xp_cmdshell)',
                    r'(?i)(?:--|#|\/\*|\*\/|;|\b(?:or|and)\s+\d+=\d+)'
                ]
                
                for pattern in sql_patterns:
                    if re.search(pattern, session.http_uri):
                        session.add_violation(
                            'HTTP_SQL_INJECTION',
                            'Possible SQL injection attempt in URI',
                            'high',
                            {'uri': session.http_uri, 'pattern': pattern}
                        )
                        break
                
                # Parse headers from remaining lines
                self._parse_http_headers(lines[1:], session)
                
            # Check for HTTP response
            elif self.http_response_pattern.match(first_line):
                match = self.http_response_pattern.match(first_line)
                if match:
                    session.http_version = f"HTTP/{match.group('version')}"
                    session.http_status_code = int(match.group('status_code'))
                    
                    # Check for suspicious status codes
                    if session.http_status_code >= 400:
                        session.add_violation(
                            'HTTP_ERROR_RESPONSE',
                            f'HTTP error response: {session.http_status_code}',
                            'low',
                            {'status_code': session.http_status_code}
                        )
                    
                    # Parse headers from remaining lines
                    self._parse_http_headers(lines[1:], session)
    
    def _parse_http_headers(self, lines: List[str], session: ProtocolState):
        """Parse HTTP headers and check for anomalies."""
        header_count = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                # Empty line indicates end of headers
                break
                
            header_count += 1
            
            # Check for too many headers
            if header_count > self.http_config['max_headers']:
                session.add_violation(
                    'HTTP_TOO_MANY_HEADERS',
                    f'Too many HTTP headers: {header_count}',
                    'medium',
                    {'header_count': header_count, 'max_allowed': self.http_config['max_headers']}
                )
                break
            
            # Parse header
            match = self.http_header_pattern.match(line)
            if match:
                name = match.group('name').lower()
                value = match.group('value')
                
                # Store header
                session.http_headers[name] = value
                
                # Check for suspicious headers
                self._check_http_header(name, value, session)
    
    def _check_http_header(self, name: str, value: str, session: ProtocolState):
        """Check an HTTP header for anomalies."""
        # Check for unusually long headers
        if len(name) + len(value) > self.http_config['max_header_size']:
            session.add_violation(
                'HTTP_HEADER_SIZE',
                f'Excessive HTTP header size: {len(name) + len(value)}',
                'low',
                {'header': name, 'size': len(name) + len(value), 'max_allowed': self.http_config['max_header_size']}
            )
        
        # Check for suspicious User-Agent
        if name == 'user-agent':
            suspicious_agents = [
                'nmap', 'nikto', 'sqlmap', 'w3af', 'metasploit', 'nessus',
                'acunetix', 'appscan', 'burp', 'dirbuster', 'nikto', 'paros',
                'wpscan', 'zap', 'owasp', 'sqlmap'
            ]
            
            if any(agent.lower() in value.lower() for agent in suspicious_agents):
                session.add_violation(
                    'HTTP_SUSPICIOUS_USER_AGENT',
                    f'Suspicious User-Agent detected: {value}',
                    'medium',
                    {'user_agent': value}
                )
        
        # Check for XSS attempts in headers
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'data:'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                session.add_violation(
                    'HTTP_XSS_ATTEMPT',
                    f'Possible XSS attempt in header: {name}',
                    'high',
                    {'header': name, 'value': value, 'pattern': pattern}
                )
                break
    
    def _analyze_dns(self, packet: Dict[str, Any], session: ProtocolState):
        """Analyze DNS protocol violations."""
        # Check for DNS query flooding
        if len(session.dns_queries) > 100:  # More than 100 queries in a session
            session.add_violation(
                'DNS_QUERY_FLOOD',
                f'Excessive DNS queries in session: {len(session.dns_queries)}',
                'high',
                {'query_count': len(session.dns_queries)}
            )
        
        # Check for DNS tunneling attempts
        query = packet.get('dns_query', '')
        if query:
            # Check for long domain names (possible tunneling)
            if len(query) > self.dns_config['max_query_length']:
                session.add_violation(
                    'DNS_LONG_QUERY',
                    f'Excessively long DNS query: {len(query)}',
                    'medium',
                    {'query_length': len(query), 'max_allowed': self.dns_config['max_query_length']}
                )
            
            # Check for too many labels
            if query.count('.') > self.dns_config['max_labels']:
                session.add_violation(
                    'DNS_TOO_MANY_LABELS',
                    f'Too many labels in DNS query: {query.count(".")}',
                    'medium',
                    {'label_count': query.count('.'), 'max_allowed': self.dns_config['max_labels']}
                )
            
            # Check for long labels
            for label in query.split('.'):
                if len(label) > self.dns_config['max_label_length']:
                    session.add_violation(
                        'DNS_LONG_LABEL',
                        f'Excessively long DNS label: {len(label)}',
                        'low',
                        {'label': label, 'label_length': len(label), 'max_allowed': self.dns_config['max_label_length']}
                    )
            
            # Check for suspicious domain patterns
            suspicious_patterns = [
                r'^[0-9a-f]{16,}\.',  # Hex encoded data
                r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\\.',  # IP-like patterns
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.'  # UUID patterns
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    session.add_violation(
                        'DNS_SUSPICIOUS_PATTERN',
                        f'Suspicious pattern in DNS query: {query}',
                        'medium',
                        {'query': query, 'pattern': pattern}
                    )
                    break
            
            # Add to session queries
            session.dns_queries.append({
                'query': query,
                'timestamp': datetime.datetime.now().timestamp(),
                'src_ip': packet.get('src_ip'),
                'src_port': packet.get('src_port')
            })
        
        # Check DNS responses for anomalies
        if 'dns_answers' in packet:
            for answer in packet['dns_answers']:
                # Check for unusually large DNS responses (possible exfiltration)
                if 'data' in answer and len(answer['data']) > self.dns_config['max_response_length']:
                    session.add_violation(
                        'DNS_LARGE_RESPONSE',
                        f'Excessively large DNS response: {len(answer["data"])} bytes',
                        'high',
                        {'response_size': len(answer['data']), 'max_allowed': self.dns_config['max_response_length']}
                    )
                
                # Add to session answers
                session.dns_answers.append({
                    'answer': answer,
                    'timestamp': datetime.datetime.now().timestamp()
                })
