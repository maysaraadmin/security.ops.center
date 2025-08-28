"""
TLS/SSL Inspection Module for NIPS
"""

import ssl
import socket
import logging
import tempfile
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, List, Tuple, Any, Union, Callable
from pathlib import Path
import threading
import time
import json
import hashlib
import re
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('nips.tls_inspect')

class TLSInspectionError(Exception):
    """Base exception for TLS inspection errors."""
    pass

class TLSAction(Enum):
    """Actions to take for TLS traffic."""
    ALLOW = auto()
    BLOCK = auto()
    DECRYPT = auto()  # Decrypt and inspect
    LOG = auto()      # Allow but log details
    QUARANTINE = auto()  # Quarantine the source

class TLSAlertLevel(Enum):
    """TLS Alert levels."""
    WARNING = 1
    FATAL = 2

class TLSCipherStrength(Enum):
    """TLS cipher strength classification."""
    WEAK = "weak"         # < 112 bits
    MEDIUM = "medium"     # 112-127 bits
    STRONG = "strong"     # 128-255 bits
    FUTURE_PROOF = "fp"   # 256+ bits

@dataclass
class TLSCertificate:
    """Represents a TLS certificate with parsed information."""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime
    public_key: Dict[str, Any]
    extensions: Dict[str, Any]
    signature_algorithm: str
    version: int
    fingerprint: str
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_ca: bool = False
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    
    @classmethod
    def from_cryptography(cls, cert: x509.Certificate) -> 'TLSCertificate':
        """Create from cryptography.x509.Certificate."""
        subject = {attr.oid._name: attr.value for attr in cert.subject}
        issuer = {attr.oid._name: attr.value for attr in cert.issuer}
        
        # Get SANs
        san_dns = []
        san_ip = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if hasattr(name, 'value'):
                    if hasattr(name, 'dns_name'):
                        san_dns.append(name.value)
                    elif hasattr(name, 'ip_address'):
                        san_ip.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        
        # Get key usage
        key_usage = []
        try:
            usage_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            for usage in [
                'digital_signature', 'content_commitment', 'key_encipherment',
                'data_encipherment', 'key_agreement', 'key_cert_sign',
                'crl_sign', 'encipher_only', 'decipher_only'
            ]:
                if getattr(usage_ext.value, usage, False):
                    key_usage.append(usage)
        except x509.ExtensionNotFound:
            pass
        
        # Get extended key usage
        ext_key_usage = []
        try:
            ext_usage = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            for usage in ext_usage.value:
                ext_key_usage.append(usage._name if hasattr(usage, '_name') else str(usage))
        except x509.ExtensionNotFound:
            pass
        
        # Get public key info
        public_key = {
            'type': cert.public_key().__class__.__name__,
            'key_size': cert.public_key().key_size,
        }
        
        # Get extensions
        extensions = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
            extensions[ext_name] = str(ext.value)
        
        return cls(
            subject=subject,
            issuer=issuer,
            serial_number=cert.serial_number,
            not_valid_before=cert.not_valid_before,
            not_valid_after=cert.not_valid_after,
            public_key=public_key,
            extensions=extensions,
            signature_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown',
            version=cert.version.value,
            fingerprint=cert.fingerprint(hashlib.sha256()).hexdigest(),
            san_dns=san_dns,
            san_ip=san_ip,
            is_self_signed=cert.issuer == cert.subject,
            is_ca=cert.extensions.get_extension_for_oid(
                x509.BasicConstraintsOID
            ).value.ca if cert.extensions.get_extension_for_oid(x509.BasicConstraintsOID) else False,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage
        )

@dataclass
class TLSHandshake:
    """Represents a TLS handshake with extracted information."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    server_name: Optional[str] = None
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_chain: List[TLSCertificate] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    session_id: Optional[bytes] = None
    compression_methods: List[str] = field(default_factory=list)
    extensions: Dict[str, Any] = field(default_factory=dict)
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None
    
    def is_valid(self) -> bool:
        """Check if the handshake appears valid."""
        if not self.server_name and not self.dst_ip:
            return False
        if not self.version:
            return False
        return True

@dataclass
class TLSSession:
    """Represents an ongoing TLS session."""
    session_id: str
    start_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    server_name: Optional[str] = None
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_chain: List[TLSCertificate] = field(default_factory=list)
    alpn_protocol: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    end_time: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[float]:
        """Get session duration in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'session_id': self.session_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'server_name': self.server_name,
            'version': self.version,
            'cipher_suite': self.cipher_suite,
            'alpn_protocol': self.alpn_protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'error': self.error,
            'metadata': self.metadata
        }

class TLSInspector:
    """
    TLS/SSL traffic inspection and decryption engine.
    
    This class provides functionality to:
    1. Inspect TLS handshakes and extract metadata
    2. Decrypt TLS traffic when private keys are available
    3. Detect suspicious or malicious TLS usage
    4. Enforce TLS security policies
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the TLS inspector.
        
        Args:
            config: Configuration dictionary with the following optional keys:
                - private_keys: List of paths to private key files
                - ca_certificates: List of paths to CA certificate files
                - enable_mitm: Whether to enable MITM decryption (requires private keys)
                - min_tls_version: Minimum allowed TLS version ('TLSv1.2', 'TLSv1.3')
                - allowed_ciphers: List of allowed cipher suites
                - block_self_signed: Whether to block self-signed certificates
                - block_expired_certs: Whether to block expired certificates
                - block_weak_crypto: Whether to block weak crypto (RSA < 2048, SHA1, etc.)
                - log_all_handshakes: Whether to log all TLS handshakes
        """
        self.config = config or {}
        self.private_keys = self._load_private_keys()
        self.ca_certificates = self._load_ca_certificates()
        self.sessions: Dict[str, TLSSession] = {}
        self.lock = threading.RLock()
        self.rules = self._load_default_rules()
        self.mitm_enabled = self.config.get('enable_mitm', False) and bool(self.private_keys)
        self.session_timeout = self.config.get('session_timeout', 3600)  # seconds
        self._session_cleaner = threading.Thread(
            target=self._cleanup_sessions,
            daemon=True
        )
        self._session_cleaner.start()
    
    def _load_private_keys(self) -> List[Any]:
        """Load private keys from configuration."""
        keys = []
        for key_path in self.config.get('private_keys', []):
            try:
                with open(key_path, 'rb') as f:
                    # TODO: Implement key loading with cryptography or OpenSSL
                    pass
                logger.info(f"Loaded private key from {key_path}")
            except Exception as e:
                logger.error(f"Failed to load private key {key_path}: {e}")
        return keys
    
    def _load_ca_certificates(self) -> List[x509.Certificate]:
        """Load CA certificates from configuration."""
        certs = []
        for cert_path in self.config.get('ca_certificates', []):
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(
                        cert_data,
                        default_backend()
                    )
                    certs.append(cert)
                logger.info(f"Loaded CA certificate from {cert_path}")
            except Exception as e:
                logger.error(f"Failed to load CA certificate {cert_path}: {e}")
        return certs
    
    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """Load default TLS inspection rules."""
        return [
            {
                'name': 'block_ssl3',
                'description': 'Block SSL 3.0 and earlier',
                'condition': lambda h: h.version and h.version.startswith('SSL'),
                'action': TLSAction.BLOCK,
                'severity': 'high',
                'enabled': True
            },
            {
                'name': 'block_tls10',
                'description': 'Block TLS 1.0',
                'condition': lambda h: h.version == 'TLSv1.0',
                'action': TLSAction.BLOCK,
                'severity': 'medium',
                'enabled': True
            },
            {
                'name': 'block_tls11',
                'description': 'Block TLS 1.1',
                'condition': lambda h: h.version == 'TLSv1.1',
                'action': TLSAction.BLOCK,
                'severity': 'medium',
                'enabled': True
            },
            {
                'name': 'block_weak_ciphers',
                'description': 'Block weak cipher suites',
                'condition': self._is_weak_cipher_suite,
                'action': TLSAction.BLOCK,
                'severity': 'high',
                'enabled': True
            },
            {
                'name': 'block_self_signed',
                'description': 'Block self-signed certificates',
                'condition': self._is_self_signed_cert,
                'action': TLSAction.BLOCK,
                'severity': 'medium',
                'enabled': self.config.get('block_self_signed', True)
            },
            {
                'name': 'block_expired_certs',
                'description': 'Block expired certificates',
                'condition': self._is_cert_expired,
                'action': TLSAction.BLOCK,
                'severity': 'high',
                'enabled': self.config.get('block_expired_certs', True)
            }
        ]
    
    def _is_weak_cipher_suite(self, handshake: TLSHandshake) -> bool:
        """Check if the cipher suite is considered weak."""
        if not handshake.cipher_suite:
            return False
            
        # List of weak ciphers
        weak_ciphers = {
            'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5', 'SHA1', '3DES', 'CBC', 'PSK', 'SRP', 'KRB5',
            'CAMELLIA', 'SEED', 'IDEA', 'AES-128', 'AES-256'  # These can be weak in certain modes
        }
        
        # Check if any weak cipher is in the cipher suite name
        cipher = handshake.cipher_suite.upper()
        return any(weak in cipher for weak in weak_ciphers)
    
    def _is_self_signed_cert(self, handshake: TLSHandshake) -> bool:
        """Check if the certificate is self-signed."""
        if not handshake.certificate_chain:
            return False
        cert = handshake.certificate_chain[0]  # Server certificate
        return cert.is_self_signed
    
    def _is_cert_expired(self, handshake: TLSHandshake) -> bool:
        """Check if the certificate is expired or not yet valid."""
        if not handshake.certificate_chain:
            return False
        cert = handshake.certificate_chain[0]  # Server certificate
        now = datetime.utcnow()
        return now < cert.not_valid_before or now > cert.not_valid_after
    
    def _cleanup_sessions(self):
        """Background thread to clean up old sessions."""
        while True:
            try:
                now = time.time()
                to_remove = [
                    session_id for session_id, session in self.sessions.items()
                    if session.end_time and (now - session.end_time > self.session_timeout)
                ]
                
                with self.lock:
                    for session_id in to_remove:
                        del self.sessions[session_id]
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in session cleanup thread: {e}", exc_info=True)
                time.sleep(10)  # Avoid tight loop on error
    
    def inspect_handshake(self, handshake: TLSHandshake) -> Dict[str, Any]:
        """
        Inspect a TLS handshake and determine what action to take.
        
        Args:
            handshake: The TLS handshake to inspect
            
        Returns:
            Dict containing:
                - action: The action to take (ALLOW, BLOCK, etc.)
                - reason: Reason for the action
                - severity: Severity level (info, low, medium, high, critical)
                - metadata: Additional metadata about the decision
        """
        if not handshake.is_valid():
            return {
                'action': TLSAction.BLOCK,
                'reason': 'Invalid handshake',
                'severity': 'high',
                'metadata': {}
            }
        
        # Apply rules in order
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            try:
                if rule['condition'](handshake):
                    return {
                        'action': rule['action'],
                        'reason': rule['description'],
                        'severity': rule.get('severity', 'medium'),
                        'metadata': {
                            'rule': rule['name'],
                            'server_name': handshake.server_name,
                            'version': handshake.version,
                            'cipher_suite': handshake.cipher_suite
                        }
                    }
            except Exception as e:
                logger.error(f"Error applying rule {rule.get('name')}: {e}", exc_info=True)
        
        # Default action if no rules match
        return {
            'action': TLSAction.ALLOW,
            'reason': 'No rules matched',
            'severity': 'info',
            'metadata': {}
        }
    
    def decrypt_traffic(self, encrypted_data: bytes, session_id: str) -> Optional[bytes]:
        """
        Decrypt TLS traffic for a session.
        
        Args:
            encrypted_data: The encrypted TLS data
            session_id: The session ID
            
        Returns:
            Decrypted data if successful, None otherwise
        """
        if not self.mitm_enabled:
            logger.warning("MITM decryption is not enabled")
            return None
            
        # TODO: Implement decryption using session keys
        # This would require maintaining session state and keys
        return None
    
    def start_session(self, handshake: TLSHandshake) -> str:
        """
        Start tracking a new TLS session.
        
        Args:
            handshake: The initial handshake for the session
            
        Returns:
            Session ID
        """
        session_id = hashlib.sha256(
            f"{handshake.src_ip}:{handshake.src_port}:{handshake.dst_ip}:{handshake.dst_port}:{time.time()}".encode()
        ).hexdigest()
        
        session = TLSSession(
            session_id=session_id,
            start_time=time.time(),
            src_ip=handshake.src_ip,
            src_port=handshake.src_port,
            dst_ip=handshake.dst_ip,
            dst_port=handshake.dst_port,
            server_name=handshake.server_name,
            version=handshake.version,
            cipher_suite=handshake.cipher_suite,
            certificate_chain=handshake.certificate_chain,
            alpn_protocol=handshake.alpn_protocols[0] if handshake.alpn_protocols else None
        )
        
        with self.lock:
            self.sessions[session_id] = session
        
        return session_id
    
    def update_session(self, session_id: str, data_sent: int = 0, data_received: int = 0) -> bool:
        """
        Update session statistics.
        
        Args:
            session_id: The session ID
            data_sent: Bytes sent in this update
            data_received: Bytes received in this update
            
        Returns:
            True if session was updated, False if not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
                
            session.bytes_sent += data_sent
            session.bytes_received += data_received
            session.packets_sent += 1 if data_sent > 0 else 0
            session.packets_received += 1 if data_received > 0 else 0
            
            return True
    
    def end_session(self, session_id: str, error: Optional[str] = None) -> bool:
        """
        End a TLS session.
        
        Args:
            session_id: The session ID
            error: Optional error message if the session ended abnormally
            
        Returns:
            True if session was ended, False if not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
                
            session.end_time = time.time()
            session.error = error
            
            # Log session summary
            logger.info(
                f"TLS session ended: {session_id} "
                f"({session.src_ip}:{session.src_port} -> {session.dst_ip}:{session.dst_port}) "
                f"Duration: {session.duration:.2f}s "
                f"Sent: {session.bytes_sent} bytes, Received: {session.bytes_received} bytes"
            )
            
            return True
    
    def get_session(self, session_id: str) -> Optional[TLSSession]:
        """
        Get a session by ID.
        
        Args:
            session_id: The session ID
            
        Returns:
            The session if found, None otherwise
        """
        with self.lock:
            return self.sessions.get(session_id)
    
    def get_active_sessions(self) -> List[TLSSession]:
        """
        Get all active sessions.
        
        Returns:
            List of active sessions
        """
        with self.lock:
            return [s for s in self.sessions.values() if not s.end_time]
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Add a custom rule to the inspection engine.
        
        Args:
            rule: Rule dictionary with keys:
                - name: Unique rule name
                - description: Human-readable description
                - condition: Callable that takes a TLSHandshake and returns a bool
                - action: TLSAction to take if condition is True
                - severity: Severity level (info, low, medium, high, critical)
                - enabled: Whether the rule is enabled (default: True)
                
        Returns:
            True if rule was added, False if a rule with that name already exists
        """
        required = {'name', 'description', 'condition', 'action'}
        if not all(field in rule for field in required):
            raise ValueError(f"Rule missing required fields: {required - set(rule.keys())}")
            
        with self.lock:
            # Check for duplicate rule name
            if any(r.get('name') == rule['name'] for r in self.rules):
                return False
                
            # Set default values
            rule.setdefault('enabled', True)
            rule.setdefault('severity', 'medium')
            
            self.rules.append(rule)
            return True
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a rule by name.
        
        Args:
            rule_name: Name of the rule to remove
            
        Returns:
            True if rule was removed, False if not found
        """
        with self.lock:
            for i, rule in enumerate(self.rules):
                if rule.get('name') == rule_name:
                    del self.rules[i]
                    return True
            return False
    
    def enable_rule(self, rule_name: str, enabled: bool = True) -> bool:
        """
        Enable or disable a rule.
        
        Args:
            rule_name: Name of the rule to modify
            enabled: Whether to enable or disable the rule
            
        Returns:
            True if rule was found and updated, False otherwise
        """
        with self.lock:
            for rule in self.rules:
                if rule.get('name') == rule_name:
                    rule['enabled'] = enabled
                    return True
            return False
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Get all rules.
        
        Returns:
            List of rule dictionaries
        """
        with self.lock:
            return [dict(r) for r in self.rules]

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'private_keys': ['/path/to/private.key'],  # For decryption
        'ca_certificates': ['/path/to/ca.crt'],    # For certificate validation
        'enable_mitm': True,                      # Enable MITM decryption if keys are available
        'block_self_signed': True,                # Block self-signed certificates
        'block_expired_certs': True,              # Block expired certificates
        'block_weak_crypto': True,                # Block weak crypto
        'min_tls_version': 'TLSv1.2',             # Minimum allowed TLS version
    }
    
    # Create inspector
    inspector = TLSInspector(config)
    
    # Example handshake (in a real system, this would come from packet capture)
    handshake = TLSHandshake(
        timestamp=time.time(),
        src_ip='192.168.1.100',
        src_port=54321,
        dst_ip='93.184.216.34',  # example.com
        dst_port=443,
        server_name='example.com',
        version='TLSv1.3',
        cipher_suite='TLS_AES_256_GCM_SHA384',
        certificate_chain=[],  # Would contain real certificates
        alpn_protocols=['http/1.1']
    )
    
    # Inspect the handshake
    result = inspector.inspect_handshake(handshake)
    print(f"Inspection result: {result}")
    
    # Start a new session
    session_id = inspector.start_session(handshake)
    print(f"Started session: {session_id}")
    
    # Update session with data transfer
    inspector.update_session(session_id, data_sent=1024, data_received=2048)
    
    # End the session
    inspector.end_session(session_id)
    print(f"Session ended")
