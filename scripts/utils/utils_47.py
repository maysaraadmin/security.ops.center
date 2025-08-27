"""
SIEM Utility Functions

This module provides common utility functions used throughout the SIEM system.
"""

import os
import re
import json
import hashlib
import ipaddress
import socket
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from pathlib import Path
import functools
import time

# Configure logging
logger = logging.getLogger('siem.utils')

def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """Configure logging for the application.
    
    Args:
        level: Logging level (e.g., logging.INFO, logging.DEBUG)
        log_file: Optional path to log file. If None, logs to console only.
    """
    handlers = [logging.StreamHandler()]
    
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(os.path.abspath(log_file))
        os.makedirs(log_dir, exist_ok=True)
        
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def get_file_hash(file_path: str, algorithm: str = 'sha256', 
                chunk_size: int = 65536) -> str:
    """Calculate the hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (e.g., 'md5', 'sha1', 'sha256')
        chunk_size: Size of chunks to read from the file
        
    Returns:
        Hex digest of the file's hash
        
    Raises:
        FileNotFoundError: If the file does not exist
        ValueError: If the algorithm is not supported
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hash_algo = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        raise

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address.
    
    Args:
        ip: String to check
        
    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range.
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if the IP is in a private range, False otherwise
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def resolve_hostname(ip: str) -> str:
    """Resolve an IP address to a hostname.
    
    Args:
        ip: IP address to resolve
        
    Returns:
        str: Hostname if resolved, original IP if resolution fails
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return ip

def parse_iso8601(timestamp: str) -> datetime:
    """Parse an ISO 8601 formatted timestamp string to a datetime object.
    
    Args:
        timestamp: ISO 8601 formatted timestamp string
        
    Returns:
        datetime: Parsed datetime object
        
    Raises:
        ValueError: If the timestamp is not in a valid ISO 8601 format
    """
    # Try parsing with timezone
    try:
        return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except ValueError:
        pass
    
    # Try common formats
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',  # With microseconds and timezone
        '%Y-%m-%dT%H:%M:%S%z',     # Without microseconds, with timezone
        '%Y-%m-%d %H:%M:%S.%f',    # With microseconds, no timezone
        '%Y-%m-%d %H:%M:%S',       # Without microseconds, no timezone
        '%Y%m%dT%H%M%S%z',         # Compact format with timezone
        '%Y%m%d%H%M%S',            # Compact format without timezone
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Could not parse timestamp: {timestamp}")

def format_timestamp(dt: Optional[datetime] = None, 
                   include_timezone: bool = True) -> str:
    """Format a datetime object as an ISO 8601 string.
    
    Args:
        dt: Datetime object to format. If None, uses current time.
        include_timezone: Whether to include timezone information
        
    Returns:
        str: Formatted ISO 8601 timestamp
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    
    if include_timezone and dt.tzinfo is None:
        dt = dt.astimezone()
    
    return dt.isoformat()

def deep_merge(dict1: Dict, dict2: Dict) -> Dict:
    """Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)
        
    Returns:
        dict: Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result

def retry(max_attempts: int = 3, delay: float = 1.0, 
         exceptions: Tuple[Exception] = (Exception,),
         backoff_factor: float = 2.0):
    """Decorator for retrying a function with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts in seconds
        exceptions: Tuple of exceptions to catch
        backoff_factor: Multiplier for delay between attempts
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            current_delay = delay
            
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempts += 1
                    if attempts == max_attempts:
                        logger.error(
                            f"Failed after {attempts} attempts: {e}"
                        )
                        raise
                    
                    logger.warning(
                        f"Attempt {attempts} failed: {e}. "
                        f"Retrying in {current_delay:.2f}s..."
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff_factor
        
        return wrapper
    return decorator

def get_size(bytes_size: int, suffix: str = 'B') -> str:
    """Convert bytes to a human-readable string.
    
    Args:
        bytes_size: Size in bytes
        suffix: Unit suffix (e.g., 'B' for bytes)
        
    Returns:
        str: Human-readable size string
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}{suffix}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} P{suffix}"

def sanitize_string(s: str, max_length: int = 1024) -> str:
    """Sanitize a string by removing control characters and truncating.
    
    Args:
        s: Input string
        max_length: Maximum length of the output string
        
    Returns:
        str: Sanitized string
    """
    if not isinstance(s, str):
        return str(s)[:max_length]
    
    # Remove control characters
    s = ''.join(ch for ch in s if ord(ch) >= 32 or ch in '\n\r\t')
    
    # Truncate if necessary
    if len(s) > max_length:
        s = s[:max_length - 3] + '...'
    
    return s

def is_subnet_of(network1: str, network2: str) -> bool:
    """Check if network1 is a subnet of network2.
    
    Args:
        network1: Network in CIDR notation (e.g., '192.168.1.0/24')
        network2: Network in CIDR notation to check against
        
    Returns:
        bool: True if network1 is a subnet of network2
    """
    try:
        n1 = ipaddress.ip_network(network1, strict=False)
        n2 = ipaddress.ip_network(network2, strict=False)
        return n1.subnet_of(n2)
    except ValueError:
        return False

def get_host_info() -> Dict[str, Any]:
    """Get information about the host system.
    
    Returns:
        dict: Host information including hostname, IP addresses, etc.
    """
    import platform
    import socket
    
    hostname = socket.gethostname()
    
    # Get all IP addresses
    ip_addresses = []
    try:
        ip_addresses = [
            addr[4][0] for addr in socket.getaddrinfo(
                socket.gethostname(), 
                None,
                family=socket.AF_INET
            )
        ]
    except socket.gaierror:
        pass
    
    return {
        'hostname': hostname,
        'fqdn': socket.getfqdn(),
        'ip_addresses': ip_addresses,
        'os': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
        },
        'python': {
            'version': platform.python_version(),
            'implementation': platform.python_implementation(),
            'compiler': platform.python_compiler(),
        }
    }
