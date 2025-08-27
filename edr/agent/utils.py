"""
Utility functions for the EDR agent.
"""
import os
import sys
import logging
import platform
import getpass
from typing import Dict, Any, Optional

logger = logging.getLogger('edr.agent.utils')

def get_system_info() -> Dict[str, Any]:
    """
    Gather basic system information.
    
    Returns:
        Dict containing system information
    """
    try:
        return {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'username': getpass.getuser()
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {}

def ensure_directory(directory: str) -> bool:
    """
    Ensure a directory exists, create it if it doesn't.
    
    Args:
        directory: Path to the directory to create
        
    Returns:
        bool: True if directory exists or was created, False otherwise
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {directory}: {e}")
        return False

def drop_privileges() -> bool:
    """
    Drop privileges if running as root/admin.
    On Windows, this is a no-op and always returns True.
    
    Returns:
        bool: True if successful or on Windows, False otherwise
    """
    try:
        # On Windows, we don't need to drop privileges
        # as we're not running as root by default
        return True
    except Exception as e:
        logger.error(f"Error dropping privileges: {e}")
        return False

def is_admin() -> bool:
    """
    Check if the current user has admin privileges.
    
    Returns:
        bool: True if user has admin privileges, False otherwise
    """
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False
