"""
File Integrity Monitoring (FIM) Module

Provides real-time monitoring of files, directories, and system configurations
to detect unauthorized changes, additions, or deletions.
"""

__version__ = "1.0.0"

from .core import FIMEngine, FileEvent, EventType, FileIntegrityError
from .monitors import (
    FileMonitor,
    DirectoryMonitor,
    RegistryMonitor
)

# For backward compatibility
__all__ = [
    'FIMEngine',
    'FileEvent',
    'EventType',
    'FileIntegrityError',
    'FileMonitor',
    'DirectoryMonitor',
    'RegistryMonitor'
]
