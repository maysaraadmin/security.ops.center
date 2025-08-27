""
EDR Agent - Data collectors for system monitoring.

This module provides platform-specific collectors for gathering system data
with minimal performance impact.
"""
import platform
from typing import Type, Dict, Any, Optional
from ..models import Platform

class BaseCollector:
    """Base class for all collectors."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize the collector."""
        self.name = name
        self.config = config
        self.enabled = True
        self.interval = config.get('interval', 60)  # Default 60 seconds
        self.last_run = 0
    
    def collect(self) -> Dict[str, Any]:
        """Collect and return data from this collector."""
        raise NotImplementedError
    
    def start(self) -> None:
        """Start the collector (for continuous collection)."""
        pass
    
    def stop(self) -> None:
        """Stop the collector."""
        pass

# Import platform-specific collectors
try:
    if platform.system().lower() == 'windows':
        from .windows import WindowsCollector as PlatformCollector
    elif platform.system().lower() == 'darwin':  # macOS
        from .darwin import DarwinCollector as PlatformCollector
    else:  # Default to Linux
        from .linux import LinuxCollector as PlatformCollector
except ImportError:
    # Fallback to base collector if platform-specific one is not available
    from .base import BaseCollector as PlatformCollector

def get_platform_collector() -> Type[BaseCollector]:
    """Get the appropriate collector class for the current platform."""
    return PlatformCollector

def create_collector(name: str, config: Dict[str, Any]) -> Optional[BaseCollector]:
    """Create a collector instance by name."""
    try:
        collector_cls = get_platform_collector()
        return collector_cls(name, config)
    except Exception as e:
        import logging
        logging.error(f"Failed to create collector {name}: {e}")
        return None
