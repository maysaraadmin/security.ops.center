"""
Threat detectors for common security threats.
"""
import re
import ipaddress
from typing import Dict, Any, List, Optional, Pattern, Set, Tuple
from datetime import datetime, timedelta
import hashlib

from .base import ThreatDetector

class BruteForceDetector(ThreatDetector):
    """Detects brute force login attempts."""
    
    def _setup(self) -> None:
        """Set up the detector."""
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.window = timedelta(
            minutes=self.config.get('window_minutes', 5)
        )
        self.threshold = self.config.get('threshold', 5)
        self.whitelist_ips = set(
            self.config.get('whitelist_ips', [])
        )

    def _get_identifier(self, event: Dict[str, Any]) -> Optional[str]:
        """Get a unique identifier for the login attempt."""
        # Use source IP and target user as the identifier
        src_ip = event.get('source', {}).get('ip')
        user = event.get('user', {}).get('name')

        if not src_ip or not user or not event.get('event', {}).get('outcome'):
            return None

        return f"{src_ip}:{user}"

    def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect brute force login attempts."""
        # Skip if not an authentication event
        if event.get('event', {}).get('category') != 'authentication':
            return None

        # Skip if source IP is whitelisted
        src_ip = event.get('source', {}).get('ip')
        if src_ip in self.whitelist_ips:
            return None

        identifier = self._get_identifier(event)
        if not identifier:
            return None

        now = datetime.utcnow()

        # Clean up old attempts
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                t for t in self.failed_attempts[identifier]
                if now - t <= self.window
            ]

        # Track failed login attempts
        if event.get('event', {}).get('outcome') == 'failure':
            self.failed_attempts.setdefault(identifier, []).append(now)

            # Check if threshold is exceeded
            if len(self.failed_attempts[identifier]) >= self.threshold:
                return self.generate_alert(
                    event,
                    signature=f"Brute Force Attempt Detected from {src_ip}",
                    description=(
                        f"Multiple failed login attempts ({len(self.failed_attempts[identifier])}) "
                        f"for user '{event.get('user', {}).get('name')}' from {src_ip}"
                    ),
                    threat={
                        'technique': ['T1110.001'],  # Brute Force: Password Guessing
                        'tactic': ['TA0006'],  # Credential Access
                        'confidence': 'high'
                    },
                    brute_force_attempts=len(self.failed_attempts[identifier]),
                    time_window_minutes=self.window.seconds // 60
                )

        return None


class MalwareDetector(ThreatDetector):
    """Detects potential malware based on file hashes and behaviors."""

    def _setup(self) -> None:
        """Set up the detector."""
        self.known_malware_hashes = set(
            self.config.get('known_malware_hashes', [])
        )
        self.suspicious_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.get('suspicious_patterns', [
                r'powershell.*-nop.*-w\s+hidden',
                r'certutil.*-decode',
                r'bitsadmin.*\/transfer',
                r'regsvr32.*\/s\b.*\/i:http',
                r'mimikatz',
                r'cobaltstrike',
                r'metasploit',
                r'nishang'
            ])
        ]

    def _check_suspicious_command(self, command: str) -> Optional[str]:
        """Check if a command contains suspicious patterns."""
        if not command:
            return None

        for pattern in self.suspicious_patterns:
            if pattern.search(command):
                return pattern.pattern
        return None

    def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect potential malware activity."""
        # Check file hashes against known malware
        if 'file' in event and 'hash' in event['file']:
            file_hash = event['file']['hash'].lower()
            if file_hash in self.known_malware_hashes:
                return self.generate_alert(
                    event,
                    signature=f"Known Malware Detected: {event.get('file', {}).get('name', 'Unknown')}",
                    description=(
                        f"File with known malware hash detected: {file_hash}"
                    ),
                    threat={
                        'technique': ['T1204.002'],  # User Execution: Malicious File
                        'tactic': ['TA0002'],  # Execution
                        'confidence': 'high'
                    }
                )

        # Check for suspicious commands
        if 'process' in event and 'command_line' in event['process']:
            suspicious_pattern = self._check_suspicious_command(
                event['process']['command_line']
            )

            if suspicious_pattern:
                return self.generate_alert(
                    event,
                    signature="Suspicious Command Execution Detected",
                    description=(
                        f"Suspicious command pattern detected: {suspicious_pattern}"
                    ),
                    threat={
                        'technique': ['T1059.001'],  # Command-Line Interface
                        'tactic': ['TA0002'],  # Execution
                        'confidence': 'medium'
                    },
                    suspicious_pattern=suspicious_pattern
                )

        return None


class DDoSDetector(ThreatDetector):
    """Detects potential DDoS attacks based on network traffic patterns."""

    def _setup(self) -> None:
        """Set up the detector."""
        self.window = timedelta(
            seconds=self.config.get('window_seconds', 60)
        )
        self.request_threshold = self.config.get('request_threshold', 1000)
        self.unique_ips_threshold = self.config.get('unique_ips_threshold', 50)

        # Track requests per target
        self.requests: Dict[str, List[Tuple[datetime, str]]] = {}

    def _get_target_key(self, event: Dict[str, Any]) -> Optional[str]:
        """Get a unique key for the target of the request."""
        dest = event.get('destination', {})
        dest_ip = dest.get('ip')
        dest_port = dest.get('port')

        if not dest_ip or not dest_port:
            return None

        return f"{dest_ip}:{dest_port}"

    def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect potential DDoS attacks."""
        # Skip if not a network event
        if event.get('event', {}).get('category') != 'network':
            return None

        target_key = self._get_target_key(event)
        if not target_key:
            return None

        now = datetime.utcnow()
        src_ip = event.get('source', {}).get('ip')

        # Initialize tracking for this target
        if target_key not in self.requests:
            self.requests[target_key] = []

        # Add this request
        self.requests[target_key].append((now, src_ip))

        # Clean up old requests
        self.requests[target_key] = [
            (ts, ip) for ts, ip in self.requests[target_key]
            if now - ts <= self.window
        ]

        # Check for potential DDoS
        total_requests = len(self.requests[target_key])
        unique_ips = len({ip for _, ip in self.requests[target_key]})

        if (total_requests >= self.request_threshold and 
            unique_ips >= self.unique_ips_threshold):

            dest_ip, dest_port = target_key.split(':', 1)
            return self.generate_alert(
                event,
                signature=f"Potential DDoS Attack Detected on {dest_ip}:{dest_port}",
                description=(
                    f"High volume of requests detected: {total_requests} requests "
                    f"from {unique_ips} unique IPs in the last {self.window.seconds} seconds"
                ),
                threat={
                    'technique': ['T1498'],  # Network Denial of Service
                    'tactic': ['TA0040'],  # Impact
                    'confidence': 'medium'
                },
                request_count=total_requests,
                unique_ip_count=unique_ips
            )

        return None


class DataExfiltrationDetector(ThreatDetector):
    """Detects potential data exfiltration attempts."""

    def _setup(self) -> None:
        """Set up the detector."""
        self.suspicious_domains = set(
            self.config.get('suspicious_domains', [
                'pastebin\\.com',
                'transfer\\.sh',
                'file\\.io',
                'anonfiles\\.com'
            ])
        )

        self.domain_pattern = re.compile(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',
            re.IGNORECASE
        )

        self.data_size_threshold = self.config.get('data_size_threshold', 10 * 1024 * 1024)  # 10MB
        self.window = timedelta(minutes=5)

        # Track data transfers by source
        self.data_transfers: Dict[str, Dict[str, Any]] = {}

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if a domain is in the suspicious domains list."""
        if not domain:
            return False

        domain = domain.lower()
        return any(
            re.search(sd, domain, re.IGNORECASE)
            for sd in self.suspicious_domains
        )

    def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect potential data exfiltration."""
        # Check for large outbound transfers
        if event.get('network', {}).get('direction') == 'outbound':
            bytes_out = event.get('network', {}).get('bytes', 0)

            if bytes_out >= self.data_size_threshold:
                src_ip = event.get('source', {}).get('ip')
                dest = event.get('destination', {})
                dest_ip = dest.get('ip')
                dest_port = dest.get('port')

                return self.generate_alert(
                    event,
                    signature=f"Large Outbound Data Transfer Detected from {src_ip}",
                    description=(
                        f"Large outbound data transfer detected: {bytes_out} bytes "
                        f"from {src_ip} to {dest_ip}:{dest_port}"
                    ),
                    threat={
                        'technique': ['T1048'],  # Exfiltration Over Network
                        'tactic': ['TA0010'],  # Exfiltration
                        'confidence': 'medium'
                    },
                    data_size_bytes=bytes_out,
                    destination=f"{dest_ip}:{dest_port}"
                )

        # Check for connections to suspicious domains
        if 'dns' in event and 'question' in event['dns']:
            for question in event['dns']['question']:
                domain = question.get('name')
                if self._is_suspicious_domain(domain):
                    return self.generate_alert(
                        event,
                        signature=f"Connection to Suspicious Domain: {domain}",
                        description=f"Connection to known suspicious domain: {domain}",
                        threat={
                            'technique': ['1071.001'],  # Data Transfer Size Limits
                            'tactic': ['TA0010'],  # Exfiltration
                            'confidence': 'high'
                        },
                        suspicious_domain=domain
                    )

        return None
