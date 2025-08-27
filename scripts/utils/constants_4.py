"""
Constants and enumerations for the SIEM system.

This module contains shared constants, enumerations, and default values used throughout the SIEM system.
"""
from enum import Enum, IntEnum, auto
from typing import Dict, List, Tuple, Set, FrozenSet, Any, Optional, Union
from datetime import timedelta

# Logging constants
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Common time constants
ONE_SECOND = 1
ONE_MINUTE = 60 * ONE_SECOND
ONE_HOUR = 60 * ONE_MINUTE
ONE_DAY = 24 * ONE_HOUR
ONE_WEEK = 7 * ONE_DAY

# Default timeouts
DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_HTTP_TIMEOUT = 10.0  # seconds
DEFAULT_DB_TIMEOUT = 30.0  # seconds

# File and directory permissions
DEFAULT_FILE_PERMISSIONS = 0o644  # -rw-r--r--
DEFAULT_DIR_PERMISSIONS = 0o755   # drwxr-xr-x

# Security constants
DEFAULT_PASSWORD_MIN_LENGTH = 12
DEFAULT_HASH_ROUNDS = 14  # For bcrypt
DEFAULT_API_KEY_LENGTH = 32
DEFAULT_TOKEN_EXPIRY = 3600  # 1 hour in seconds

# Network constants
DEFAULT_PORT = 514  # Default syslog port
MAX_PACKET_SIZE = 65535  # Maximum UDP packet size
DEFAULT_BUFFER_SIZE = 8192  # Default buffer size for socket operations

# Common regular expressions
IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::1'
HOSTNAME_PATTERN = r'\b(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
URL_PATTERN = r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)'

# Default file paths
DEFAULT_CONFIG_DIR = "/etc/siem"
DEFAULT_LOG_DIR = "/var/log/siem"
DEFAULT_DATA_DIR = "/var/lib/siem"
DEFAULT_RUN_DIR = "/var/run/siem"

# Common MIME types
MIME_TYPES = {
    '.txt': 'text/plain',
    '.log': 'text/plain',
    '.csv': 'text/csv',
    '.json': 'application/json',
    '.yaml': 'application/x-yaml',
    '.yml': 'application/x-yaml',
    '.xml': 'application/xml',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.tar': 'application/x-tar',
    '.gz': 'application/gzip',
    '.bz2': 'application/x-bzip2',
    '.xz': 'application/x-xz',
}

# Common HTTP headers
COMMON_HEADERS = {
    'User-Agent': 'SIEM-System/1.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
}

class Severity(IntEnum):
    """Standard severity levels for logs and alerts."""
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ALERT = 6
    EMERGENCY = 7

    @classmethod
    def from_string(cls, value: str) -> 'Severity':
        """Convert a string to a Severity enum value (case-insensitive)."""
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.INFO

class LogSource(Enum):
    """Standard log sources within the SIEM system."""
    SYSTEM = auto()
    SECURITY = auto()
    NETWORK = auto()
    APPLICATION = auto()
    DATABASE = auto()
    AUTHENTICATION = auto()
    AUTHORIZATION = auto()
    CONFIGURATION = auto()
    AUDIT = auto()
    ALERT = auto()
    INCIDENT = auto()
    COMPLIANCE = auto()
    PERFORMANCE = auto()
    AVAILABILITY = auto()

class Protocol(Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    FTP = "ftp"
    SSH = "ssh"
    TELNET = "telnet"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    SNMP = "snmp"
    LDAP = "ldap"
    NTP = "ntp"
    DHCP = "dhcp"
    SYSLOG = "syslog"
    OTHER = "other"

class Action(Enum):
    """Standard actions that can be taken by the SIEM system."""
    ALLOW = "allow"
    DENY = "deny"
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    NOTIFY = "notify"
    IGNORE = "ignore"

class Status(Enum):
    """Status of various SIEM components and operations."""
    UNKNOWN = "unknown"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    UPDATING = "updating"

class EventType(Enum):
    """Types of security events."""
    LOGIN = "login"
    LOGOUT = "logout"
    AUTH_FAILURE = "auth_failure"
    PASSWORD_CHANGE = "password_change"
    USER_ADD = "user_add"
    USER_DELETE = "user_delete"
    USER_MODIFY = "user_modify"
    GROUP_ADD = "group_add"
    GROUP_DELETE = "group_delete"
    GROUP_MODIFY = "group_modify"
    FILE_ACCESS = "file_access"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_DENIED = "network_denied"
    CONFIG_CHANGE = "config_change"
    POLICY_VIOLATION = "policy_violation"
    MALWARE_DETECTED = "malware_detected"
    INTRUSION_DETECTED = "intrusion_detected"
    VULNERABILITY_FOUND = "vulnerability_found"
    COMPLIANCE_ISSUE = "compliance_issue"
    ALERT = "alert"
    INCIDENT = "incident"
    OTHER = "other"

# Default values for configuration
DEFAULT_CONFIG = {
    'general': {
        'log_level': DEFAULT_LOG_LEVEL,
        'log_file': f"{DEFAULT_LOG_DIR}/siem.log",
        'pid_file': f"{DEFAULT_RUN_DIR}/siem.pid",
        'daemonize': False,
        'umask': 0o022,
    },
    'network': {
        'listen_address': '0.0.0.0',
        'port': DEFAULT_PORT,
        'max_connections': 1000,
        'timeout': DEFAULT_TIMEOUT,
    },
    'database': {
        'url': 'sqlite:////var/lib/siem/siem.db',
        'pool_size': 20,
        'max_overflow': 10,
        'pool_timeout': 30,
        'pool_recycle': 3600,
    },
    'security': {
        'password_min_length': DEFAULT_PASSWORD_MIN_LENGTH,
        'password_require_uppercase': True,
        'password_require_lowercase': True,
        'password_require_digits': True,
        'password_require_special': True,
        'password_min_entropy': 3.0,
        'api_key_length': DEFAULT_API_KEY_LENGTH,
        'token_expiry': DEFAULT_TOKEN_EXPIRY,
    },
}
