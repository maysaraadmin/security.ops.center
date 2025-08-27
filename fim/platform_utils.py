"""
Platform-specific utilities for File Integrity Monitoring.

This module provides platform-agnostic interfaces for file system monitoring,
with implementations for different operating systems.
"""
import os
import sys
import platform
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Callable, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class FileSystemWatcher(ABC):
    """Abstract base class for file system watchers."""
    
    @abstractmethod
    def start(self) -> None:
        """Start the file system watcher."""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the file system watcher."""
        pass
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if the watcher is running."""
        pass


def get_platform_watcher(path: str, callback: Callable, recursive: bool = True) -> 'FileSystemWatcher':
    """
    Get the appropriate file system watcher for the current platform.
    
    Args:
        path: Path to watch
        callback: Function to call when changes are detected
        recursive: Whether to watch subdirectories
        
    Returns:
        Platform-specific FileSystemWatcher instance
    """
    system = platform.system().lower()
    
    if system == 'windows':
        from .watchers.windows import WindowsFileSystemWatcher
        return WindowsFileSystemWatcher(path, callback, recursive)
    elif system == 'linux':
        from .watchers.linux import LinuxInotifyWatcher
        return LinuxInotifyWatcher(path, callback, recursive)
    else:
        raise NotImplementedError(f"Unsupported platform: {system}")


def get_critical_paths() -> List[str]:
    """
    Get a list of critical system paths to monitor based on the current platform.
    
    Returns:
        List of absolute paths to critical system directories
    """
    system = platform.system().lower()
    
    if system == 'windows':
        return [
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\drivers\\etc'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\config')
        ]
    elif system == 'linux':
        return [
            '/etc/',
            '/bin/',
            '/sbin/',
            '/usr/bin/',
            '/usr/sbin/',
            '/usr/local/bin/',
            '/usr/local/sbin/'
        ]
    else:
        logger.warning(f"Unsupported platform: {system}")
        return []


def is_hidden(path: str) -> bool:
    """
    Check if a file or directory is hidden.
    
    Args:
        path: Path to check
        
    Returns:
        True if the path is hidden, False otherwise
    """
    name = os.path.basename(path)
    
    # Check for hidden files on Unix-like systems
    if name.startswith('.'):
        return True
        
    # Check for hidden files on Windows
    if platform.system() == 'Windows':
        try:
            import ctypes
            # Get file attributes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            # Check if FILE_ATTRIBUTE_HIDDEN is set
            return attrs & 0x2 != 0
        except Exception:
            pass
            
    return False


def get_file_owner(path: str) -> str:
    """
    Get the owner of a file.
    
    Args:
        path: Path to the file
        
    Returns:
        Username of the file owner, or empty string if unknown
    """
    try:
        if platform.system() == 'Windows':
            import win32security
            sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            return f"{domain}\\{name}" if domain else name
        else:
            import pwd
            stat_info = os.stat(path)
            return pwd.getpwuid(stat_info.st_uid).pw_name
    except Exception as e:
        logger.debug(f"Could not get owner for {path}: {e}")
        return ""


def get_process_info(pid: int) -> Dict[str, Any]:
    """
    Get information about a process.
    
    Args:
        pid: Process ID
        
    Returns:
        Dictionary with process information (name, path, command line, etc.)
    """
    try:
        import psutil
        process = psutil.Process(pid)
        
        return {
            'pid': pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'username': process.username(),
            'create_time': process.create_time(),
            'status': process.status()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.debug(f"Could not get info for process {pid}: {e}")
        return {}
    except ImportError:
        logger.warning("psutil module not available, process information will be limited")
        return {}
