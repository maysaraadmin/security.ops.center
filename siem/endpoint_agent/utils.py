"""
Utility functions for the SIEM Endpoint Agent.
"""
import os
import sys
import json
import logging
import hashlib
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Union, Tuple
from pathlib import Path
from datetime import datetime, timezone

# Configure logging
logger = logging.getLogger('siem_agent.utils')

def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None) -> None:
    """Configure logging for the SIEM agent.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, logs to stderr)
    """
    # Convert string log level to numeric
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    # Configure logging
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_handlers = [logging.StreamHandler()]
    
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        log_handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=log_handlers
    )

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing the configuration
    """
    import yaml
    
    # Default configuration
    default_config = {
        'siem_server': 'localhost',
        'siem_port': 514,
        'use_tls': True,
        'verify_ssl': True,
        'heartbeat_interval': 300,
        'batch_size': 50,
        'max_retries': 3,
        'retry_delay': 5,
        'collectors': {
            'windows_events': True,
            'sysmon': True,
            'system_info': True
        }
    }
    
    # If no config file specified, use default
    if not config_path or not os.path.exists(config_path):
        logger.warning(f'Config file not found: {config_path}. Using default configuration.')
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}
        
        # Merge with default config (user config overrides defaults)
        config = {**default_config, **user_config}
        
        # Ensure required fields exist
        for key in ['siem_server', 'siem_port']:
            if key not in config:
                raise ValueError(f'Missing required configuration key: {key}')
        
        return config
        
    except Exception as e:
        logger.error(f'Error loading configuration: {e}')
        return default_config

def get_hostname() -> str:
    """Get the system's hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return 'unknown-host'

def get_mac_address() -> str:
    """Get the system's MAC address."""
    import uuid
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(5, -1, -1)])

def get_system_info() -> Dict[str, Any]:
    """Get basic system information."""
    return {
        'hostname': get_hostname(),
        'platform': sys.platform,
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'mac_address': get_mac_address(),
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate the hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
        
    Returns:
        Hex-encoded hash string
    """
    hash_func = getattr(hashlib, algorithm.lower(), None)
    if not hash_func:
        raise ValueError(f'Unsupported hash algorithm: {algorithm}')
    
    try:
        with open(file_path, 'rb') as f:
            file_hash = hash_func()
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        logger.error(f'Error calculating hash for {file_path}: {e}')
        return ''

def is_running_as_admin() -> bool:
    """Check if the current process is running with administrator/root privileges."""
    if os.name == 'nt':
        # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Unix/Linux/macOS
        return os.geteuid() == 0

def ensure_directory_exists(directory: str) -> None:
    """Ensure that a directory exists, creating it if necessary."""
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logger.error(f'Error creating directory {directory}: {e}')
        raise

def normalize_path(path: str) -> str:
    """Normalize a filesystem path, expanding environment variables and user home."""
    return os.path.normpath(os.path.expanduser(os.path.expandvars(path)))

def get_file_info(file_path: str) -> Dict[str, Any]:
    """Get information about a file."""
    try:
        stat = os.stat(file_path)
        return {
            'path': file_path,
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'mode': stat.st_mode,
            'uid': stat.st_uid,
            'gid': stat.st_gid,
            'inode': stat.st_ino,
            'device': stat.st_dev,
        }
    except Exception as e:
        logger.error(f'Error getting file info for {file_path}: {e}')
        return {}

def get_process_info(pid: int) -> Dict[str, Any]:
    """Get information about a running process."""
    try:
        import psutil
        process = psutil.Process(pid)
        
        with process.oneshot():
            return {
                'pid': process.pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'status': process.status(),
                'username': process.username(),
                'create_time': process.create_time(),
                'cwd': process.cwd(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'num_threads': process.num_threads(),
                'connections': [
                    {
                        'fd': conn.fd,
                        'family': conn.family.name,
                        'type': conn.type.name,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    for conn in process.connections()
                ] if process.connections() else []
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.warning(f'Error getting process info for PID {pid}: {e}')
        return {}
    except Exception as e:
        logger.error(f'Unexpected error getting process info for PID {pid}: {e}')
        return {}

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def is_valid_port(port: Union[str, int]) -> bool:
    """Check if a port number is valid."""
    try:
        port = int(port)
        return 0 < port <= 65535
    except (ValueError, TypeError):
        return False

def get_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def human_readable_size(size_bytes: int) -> str:
    """Convert a size in bytes to a human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def parse_duration(duration_str: str) -> int:
    """Parse a duration string (e.g., '5m', '2h', '1d') into seconds."""
    if not duration_str:
        return 0
    
    try:
        unit = duration_str[-1].lower()
        value = int(duration_str[:-1])
        
        if unit == 's':
            return value
        elif unit == 'm':
            return value * 60
        elif unit == 'h':
            return value * 3600
        elif unit == 'd':
            return value * 86400
        else:
            # If no unit specified, assume seconds
            return int(duration_str)
    except (ValueError, IndexError):
        logger.warning(f'Invalid duration string: {duration_str}')
        return 0

def create_ssl_context(verify: bool = True, 
                     ca_cert: Optional[str] = None,
                     client_cert: Optional[str] = None,
                     client_key: Optional[str] = None) -> ssl.SSLContext:
    """Create an SSL context for secure communication."""
    context = ssl.create_default_context()
    
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    if ca_cert and os.path.exists(ca_cert):
        context.load_verify_locations(ca_cert)
    
    if client_cert and client_key and os.path.exists(client_cert) and os.path.exists(client_key):
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    
    return context

class RateLimiter:
    """A simple rate limiter to control the rate of operations."""
    
    def __init__(self, max_operations: int, time_window: float):
        """Initialize the rate limiter.
        
        Args:
            max_operations: Maximum number of operations allowed in the time window
            time_window: Time window in seconds
        """
        self.max_operations = max_operations
        self.time_window = time_window
        self.operations = []
        
    def acquire(self) -> bool:
        """Check if an operation is allowed and record it if so."""
        now = time.time()
        
        # Remove operations outside the time window
        self.operations = [op_time for op_time in self.operations 
                          if now - op_time <= self.time_window]
        
        if len(self.operations) >= self.max_operations:
            return False
        
        self.operations.append(now)
        return True
    
    def wait(self) -> None:
        """Wait until an operation is allowed."""
        while not self.acquire():
            time.sleep(0.1)

def is_process_running(process_name: str) -> bool:
    """Check if a process with the given name is running."""
    try:
        import psutil
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == process_name:
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

def get_environment_info() -> Dict[str, Any]:
    """Get information about the current environment."""
    return {
        'python': {
            'version': sys.version,
            'executable': sys.executable,
            'path': sys.path,
        },
        'environment_vars': dict(os.environ),
        'command_line': sys.argv,
        'current_working_directory': os.getcwd(),
        'user': {
            'name': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'home': os.path.expanduser('~'),
        },
        'system': get_system_info(),
        'timestamp': get_timestamp(),
    }
