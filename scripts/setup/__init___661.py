""
Utility functions and classes for the EDR system.
"""

import os
import sys
import platform
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.utils')

def get_platform() -> str:
    """Get the current platform name."""
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'darwin'
    elif system == 'linux':
        return 'linux'
    return 'unknown'

def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform() == 'windows'

def is_linux() -> bool:
    """Check if running on Linux."""
    return get_platform() == 'linux'

def is_darwin() -> bool:
    """Check if running on macOS."""
    return get_platform() == 'darwin'

def calculate_hashes(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
    """
    Calculate file hashes using specified algorithms.
    
    Args:
        file_path: Path to the file
        algorithms: List of hash algorithms to use (default: ['md5', 'sha1', 'sha256'])
        
    Returns:
        Dict with algorithm names as keys and hash values as values
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']
    
    hashes = {}
    hash_objects = {alg: getattr(hashlib, alg)() for alg in algorithms if hasattr(hashlib, alg)}
    
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(65536)  # 64KB chunks
                if not chunk:
                    break
                for alg, hash_obj in hash_objects.items():
                    hash_obj.update(chunk)
        
        # Get hex digests
        for alg, hash_obj in hash_objects.items():
            hashes[alg] = hash_obj.hexdigest()
            
    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
    
    return hashes

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects and sets."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, set):
            return list(obj)
        return super().default(obj)

def to_json(data: Any, pretty: bool = False) -> str:
    """
    Convert data to JSON string.
    
    Args:
        data: Data to convert
        pretty: Whether to format the output with indentation
        
    Returns:
        JSON string
    """
    if pretty:
        return json.dumps(data, cls=JSONEncoder, indent=2, sort_keys=True)
    return json.dumps(data, cls=JSONEncoder)

def from_json(json_str: str) -> Any:
    """
    Parse JSON string to Python object.
    
    Args:
        json_str: JSON string to parse
        
    Returns:
        Parsed Python object
    """
    return json.loads(json_str)

def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get detailed information about a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with file information
    """
    try:
        stat_info = os.stat(file_path)
        
        # Get file type
        if os.path.isdir(file_path):
            file_type = 'directory'
        elif os.path.isfile(file_path):
            file_type = 'file'
        elif os.path.islink(file_path):
            file_type = 'symlink'
        else:
            file_type = 'unknown'
        
        # Get owner and group (if available)
        try:
            import pwd
            import grp
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            group = grp.getgrgid(stat_info.st_gid).gr_name
        except (ImportError, KeyError):
            owner = str(stat_info.st_uid)
            group = str(stat_info.st_gid)
        
        # Get permissions
        perms = {
            'user_read': bool(stat_info.st_mode & 0o400),
            'user_write': bool(stat_info.st_mode & 0o200),
            'user_execute': bool(stat_info.st_mode & 0o100),
            'group_read': bool(stat_info.st_mode & 0o040),
            'group_write': bool(stat_info.st_mode & 0o020),
            'group_execute': bool(stat_info.st_mode & 0o010),
            'other_read': bool(stat_info.st_mode & 0o004),
            'other_write': bool(stat_info.st_mode & 0o002),
            'other_execute': bool(stat_info.st_mode & 0o001),
            'setuid': bool(stat_info.st_mode & 0o4000),
            'setgid': bool(stat_info.st_mode & 0o2000),
            'sticky': bool(stat_info.st_mode & 0o1000),
        }
        
        # Get file hashes if it's a regular file
        hashes = {}
        if file_type == 'file':
            hashes = calculate_hashes(file_path)
        
        # Get extended attributes if available
        xattrs = {}
        try:
            if hasattr(os, 'listxattr'):
                xattrs = {attr: os.getxattr(file_path, attr) 
                         for attr in os.listxattr(file_path)}
        except (NotImplementedError, OSError):
            pass
        
        return {
            'path': os.path.abspath(file_path),
            'type': file_type,
            'size': stat_info.st_size,
            'created': stat_info.st_ctime,
            'modified': stat_info.st_mtime,
            'accessed': stat_info.st_atime,
            'inode': stat_info.st_ino,
            'device': stat_info.st_dev,
            'hard_links': stat_info.st_nlink,
            'owner': owner,
            'group': group,
            'permissions': perms,
            'permissions_octal': oct(stat_info.st_mode & 0o7777),
            'hashes': hashes if hashes else None,
            'extended_attributes': xattrs if xattrs else None
        }
        
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {
            'path': os.path.abspath(file_path),
            'error': str(e)
        }

class RateLimiter:
    """
    A simple rate limiter to control the frequency of operations.
    """
    
    def __init__(self, max_calls: int, period: float):
        """
        Initialize the rate limiter.
        
        Args:
            max_calls: Maximum number of calls allowed in the period
            period: Time period in seconds
        """
        self.max_calls = max_calls
        self.period = period
        self.calls = []
        self.lock = None
        
        # Initialize lock based on platform
        try:
            import threading
            self.lock = threading.Lock()
        except ImportError:
            # Fallback for environments without threading
            class DummyLock:
                def __enter__(self):
                    pass
                def __exit__(self, *args):
                    pass
            self.lock = DummyLock()
    
    def __call__(self, func: Callable) -> Callable:
        """
        Decorator to rate limit a function.
        """
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                
                # Remove old calls
                self.calls = [t for t in self.calls if now - t < self.period]
                
                # Check if we've exceeded the rate limit
                if len(self.calls) >= self.max_calls:
                    time_to_wait = self.period - (now - self.calls[0])
                    if time_to_wait > 0:
                        time.sleep(time_to_wait)
                
                # Record the call
                self.calls.append(time.time())
                
                # Call the function
                return func(*args, **kwargs)
        
        return wrapper

# Import time here to avoid circular imports
try:
    import time
except ImportError:
    time = None  # type: ignore
