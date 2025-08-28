"""
EDR Agent Core Module

This module contains the core functionality for the EDR (Endpoint Detection and Response) agent.
"""
import logging
from typing import Dict, Any, List, Optional
import platform
import os
import psutil
import time
from datetime import datetime

class EDRAgent:
    """Main EDR agent class for threat detection and response."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the EDR agent with configuration.
        
        Args:
            config: Configuration dictionary for the agent
        """
        self.config = config or {}
        self.logger = logging.getLogger("edr.agent")
        self.running = False
        self.detectors = []
        
        # System information
        self.hostname = platform.node()
        self.os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
        
        self._setup()
    
    def _setup(self) -> None:
        """Perform initial setup of the EDR agent."""
        self.logger.info("Initializing EDR agent")
        self.logger.debug(f"OS Info: {self.os_info}")
        
        # Initialize detection modules
        self._initialize_detectors()
    
    def _initialize_detectors(self) -> None:
        """Initialize all available threat detectors."""
        try:
            from .detection import ThreatDetector
            self.detectors.append(ThreatDetector(self.config.get('detection', {})))
            self.logger.info(f"Initialized {len(self.detectors)} threat detectors")
        except ImportError as e:
            self.logger.error(f"Failed to initialize threat detectors: {e}")
    
    def start(self) -> None:
        """Start the EDR agent."""
        if self.running:
            self.logger.warning("EDR agent is already running")
            return
        
        self.running = True
        self.logger.info("Starting EDR agent")
        
        # Start all detectors
        for detector in self.detectors:
            try:
                detector.start()
            except Exception as e:
                self.logger.error(f"Failed to start detector: {e}")
    
    def stop(self) -> None:
        """Stop the EDR agent."""
        if not self.running:
            return
            
        self.logger.info("Stopping EDR agent")
        self.running = False
        
        # Stop all detectors
        for detector in self.detectors:
            try:
                detector.stop()
            except Exception as e:
                self.logger.error(f"Error stopping detector: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and metrics.
        
        Returns:
            Dictionary containing system status information
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'hostname': self.hostname,
                'cpu': {
                    'percent': cpu_percent,
                    'cores': psutil.cpu_count(logical=False),
                    'logical_cores': psutil.cpu_count(logical=True)
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'boot_time': psutil.boot_time(),
                'process_count': len(psutil.pids())
            }
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {}
    
    def scan_processes(self) -> List[Dict[str, Any]]:
        """Scan running processes for potential threats.
        
        Returns:
            List of process information dictionaries
        """
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            self.logger.error(f"Error scanning processes: {e}")
        
        return processes
