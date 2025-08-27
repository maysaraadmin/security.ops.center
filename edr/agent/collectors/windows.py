"""
Windows-specific collectors for the EDR agent.
"""

import os
import socket
import psutil
import logging
import platform
from typing import Dict, List, Any

from .base import BaseCollector

logger = logging.getLogger('edr.agent.collector.windows')

class WindowsCollector(BaseCollector):
    """Windows-specific collector implementation."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize the Windows collector."""
        super().__init__(name, config)
        self._process_cache = {}
        self._last_process_scan = 0
        self._process_scan_interval = 60  # seconds
        
    def collect(self) -> Dict[str, Any]:
        """Collect system information."""
        return {
            'processes': self._collect_processes(),
            'system_info': self._collect_system_info()
        }
        
    def _collect_processes(self) -> List[Dict[str, Any]]:
        """Collect basic process information."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    processes.append({
                        'pid': proc.pid,
                        'name': proc.name(),
                        'username': proc.username(),
                        'status': proc.status()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
            
        return processes
        
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect basic system information."""
        try:
            return {
                'hostname': socket.gethostname(),
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'boot_time': psutil.boot_time()
            }
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}
            
    def start(self) -> None:
        """Start the collector."""
        logger.info(f"Starting {self.name} collector")
        
    def stop(self) -> None:
        """Stop the collector."""
        logger.info(f"Stopping {self.name} collector")
