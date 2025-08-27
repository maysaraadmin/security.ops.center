"""
Platform-specific monitoring implementations.

This package contains platform-specific implementations for monitoring
system activities across different operating systems.
"""

import platform
from typing import Dict, Any, Optional, List

class PlatformNotSupportedError(Exception):
    """Raised when a platform-specific feature is not supported."""
    pass

class SystemMonitor:
    """Base class for system monitoring."""
    
    @classmethod
    def create_for_current_platform(cls) -> 'SystemMonitor':
        """Create a monitor instance for the current platform."""
        system = platform.system().lower()
        
        if system == 'windows':
            from .windows import WindowsMonitor
            return WindowsMonitor()
        elif system == 'linux':
            from .linux import LinuxMonitor
            return LinuxMonitor()
        elif system == 'darwin':
            from .darwin import DarwinMonitor
            return DarwinMonitor()
        else:
            raise PlatformNotSupportedError(f"Unsupported platform: {system}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        raise NotImplementedError
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        raise NotImplementedError
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        raise NotImplementedError
    
    def get_file_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a file."""
        raise NotImplementedError
    
    def monitor_file_changes(self, path: str, callback: callable) -> None:
        """Monitor a file or directory for changes."""
        raise NotImplementedError
    
    def get_system_logs(self, log_type: str = 'system', limit: int = 100) -> List[Dict[str, Any]]:
        """Get system logs."""
        raise NotImplementedError
