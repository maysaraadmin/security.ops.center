""
File Integrity Monitoring (FIM) Module

Provides real-time monitoring of files, directories, and system configurations
to detect unauthorized changes, additions, or deletions.
"""

__version__ = "1.0.0"

from .core import FIMEngine, FileEvent, EventType, FileIntegrityError
from .monitors import (
    FileMonitor,
    DirectoryMonitor,
    RegistryMonitor,
    FileSystemWatcher
)
from .handlers import (
    EventHandler,
    LoggingHandler,
    AlertHandler,
    EmailNotificationHandler,
    WebhookHandler
)
from .utils import (
    calculate_file_hash,
    get_file_metadata,
    is_system_file,
    should_ignore_path
)

__all__ = [
    'FIMEngine',
    'FileEvent',
    'EventType',
    'FileIntegrityError',
    'FileMonitor',
    'DirectoryMonitor',
    'RegistryMonitor',
    'FileSystemWatcher',
    'EventHandler',
    'LoggingHandler',
    'AlertHandler',
    'EmailNotificationHandler',
    'WebhookHandler',
    'calculate_file_hash',
    'get_file_metadata',
    'is_system_file',
    'should_ignore_path'
]
