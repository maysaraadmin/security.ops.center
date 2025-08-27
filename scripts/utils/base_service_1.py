"""
Base service class for all SIEM services.

This module provides the BaseService class that implements the Service interface
and provides common functionality for all SIEM services.
"""
import abc
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Type, TypeVar, Generic, Callable
import yaml

from .interfaces import Service

T = TypeVar('T')  # Generic type for configuration

class BaseService(Service):
    """Base class for all SIEM services.
    
    This class provides common functionality for all services including:
    - Configuration management
    - Logging setup
    - Signal handling
    - Lifecycle management
    - Health monitoring
    - Metrics collection
    
    Subclasses should implement the _start() and _stop() methods.
    """
    
    def __init__(self, service_name: str, config_path: Optional[str] = None):
        """Initialize the base service.
        
        Args:
            service_name: Name of the service (used for logging and config)
            config_path: Optional path to a configuration file
        """
        self.service_name = service_name
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self._running = False
        self._start_time: Optional[float] = None
        self._health_checks: List[Callable[[], bool]] = []
        self._metrics: Dict[str, Any] = {
            'start_count': 0,
            'stop_count': 0,
            'uptime': 0,
            'last_error': None,
            'error_count': 0,
        }
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load service configuration.
        
        Returns:
            Dict containing the service configuration
        """
        config = {}
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                raise RuntimeError(f"Failed to load config from {self.config_path}: {e}")
        return config
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the service.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(f'siem.{self.service_name.lower()}')
        
        # Don't add handlers if they're already configured
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            
            # Create console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            
            # Create formatter and add it to the handler
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            ch.setFormatter(formatter)
            
            # Add the handler to the logger
            logger.addHandler(ch)
        
        return logger
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self) -> bool:
        """Start the service.
        
        Returns:
            bool: True if the service started successfully, False otherwise
        """
        if self._running:
            self.logger.warning(f"{self.service_name} service is already running")
            return False
        
        try:
            self.logger.info(f"Starting {self.service_name} service")
            if self._start():
                self._running = True
                self._start_time = time.time()
                self._metrics['start_count'] += 1
                self.logger.info(f"{self.service_name} service started successfully")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to start {self.service_name} service: {e}")
            self._metrics['error_count'] += 1
            self._metrics['last_error'] = str(e)
            return False
    
    def stop(self) -> bool:
        """Stop the service.
        
        Returns:
            bool: True if the service stopped successfully, False otherwise
        """
        if not self._running:
            self.logger.warning(f"{self.service_name} service is not running")
            return True
        
        try:
            self.logger.info(f"Stopping {self.service_name} service")
            if self._stop():
                self._running = False
                self._metrics['stop_count'] += 1
                if self._start_time:
                    self._metrics['uptime'] += time.time() - self._start_time
                    self._start_time = None
                self.logger.info(f"{self.service_name} service stopped")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error stopping {self.service_name} service: {e}")
            self._metrics['error_count'] += 1
            self._metrics['last_error'] = str(e)
            return False
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the service.
        
        Returns:
            Dict[str, Any]: A dictionary containing status information
        """
        status = {
            'service': self.service_name,
            'status': 'running' if self._running else 'stopped',
            'uptime': self._metrics['uptime'] + (time.time() - self._start_time 
                       if self._running and self._start_time else 0),
            'start_count': self._metrics['start_count'],
            'error_count': self._metrics['error_count'],
            'last_error': self._metrics['last_error']
        }
        
        # Add health check results
        status['health_checks'] = {}
        for check in self._health_checks:
            try:
                status['health_checks'][check.__name__] = check()
            except Exception as e:
                status['health_checks'][check.__name__] = f"Error: {str(e)}"
        
        return status
    
    @abc.abstractmethod
    def _start(self) -> bool:
        """Internal method to start the service. Implemented by subclasses."""
        pass
    
    @abc.abstractmethod
    def _stop(self) -> bool:
        """Internal method to stop the service. Implemented by subclasses."""
        pass
    
    def add_health_check(self, check_func: Callable[[], bool]) -> None:
        """Add a health check function to the service.
        
        Args:
            check_func: A function that returns True if healthy, False otherwise
        """
        self._health_checks.append(check_func)
    
    def is_healthy(self) -> bool:
        """Check if the service is healthy by running all health checks.
        
        Returns:
            bool: True if all health checks pass, False otherwise
        """
        if not self._running:
            return False
            
        for check in self._health_checks:
            try:
                if not check():
                    return False
            except Exception as e:
                self.logger.error(f"Health check {check.__name__} failed: {e}")
                return False
        return True
