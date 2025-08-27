"""
SIEM Core Module

This module implements the main SIEM application that coordinates all components
including log collection, event correlation, alerting, and more.
"""

import os
import sys
import yaml
import logging
import signal
import threading
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from datetime import datetime, timedelta

# Import SIEM components
from core.log_collector import LogCollector
from core.correlation_engine import CorrelationEngine
from src.edr.server import EDRAgentServer
from src.ndr.manager import NDRManager
from src.dlp.manager import DLPManager
from src.fim.manager import FIMManager
from src.hips.manager import HIPSManager
from src.nips.manager import NIPSManager
from compliance.manager import ComplianceManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem.log')
    ]
)
logger = logging.getLogger('siem.core')

class SIEM:
    """Main SIEM application class that coordinates all components."""
    
    def __init__(self, config_path: str = None):
        """Initialize the SIEM with configuration.
        
        Args:
            config_path: Path to the SIEM configuration file.
        """
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Initialize components
        self.components = {}
        self._init_components()
        
        # Event bus for inter-component communication
        self.event_bus = EventBus()
        
        # Shutdown event
        self.shutdown_event = threading.Event()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration from file."""
        if not config_path:
            # Default config path
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'config',
                'siem_config.yaml'
            )
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
                # Expand environment variables in config
                config = self._expand_env_vars(config)
                
                # Set up default values
                config.setdefault('global', {})
                config['global'].setdefault('log_level', 'INFO')
                
                return config
                
        except Exception as e:
            logger.critical(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def _expand_env_vars(self, config: Any) -> Any:
        """Recursively expand environment variables in config values."""
        if isinstance(config, dict):
            return {k: self._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._expand_env_vars(item) for item in config]
        elif isinstance(config, str) and config.startswith('${') and config.endswith('}'):
            env_var = config[2:-1]
            return os.environ.get(env_var, '')
        return config
    
    def _setup_logging(self) -> None:
        """Configure logging based on the configuration."""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Console handler
        if log_config.get('console', {}).get('enabled', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
        
        # File handler
        if log_config.get('file', {}).get('enabled', False):
            log_file = log_config['file'].get('path', 'siem.log')
            max_size = log_config['file'].get('max_size', 100) * 1024 * 1024  # MB to bytes
            backup_count = log_config['file'].get('backup_count', 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_size, backupCount=backup_count
            )
            file_handler.setLevel(log_level)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    
    def _init_components(self) -> None:
        """Initialize all SIEM components based on configuration."""
        # Log Collector
        if self.config.get('log_collection', {}).get('enabled', True):
            self.components['log_collector'] = LogCollector(
                config=self.config.get('log_collection', {})
            )
        
        # Correlation Engine
        if self.config.get('correlation', {}).get('enabled', True):
            self.components['correlation_engine'] = CorrelationEngine(
                config=self.config.get('correlation', {})
            )
        
        # EDR Agent Server
        if self.config.get('modules', {}).get('edr', {}).get('enabled', True):
            self.components['edr'] = EDRAgentServer(
                config=self.config.get('modules', {}).get('edr', {})
            )
        
        # Network Detection and Response (NDR)
        if self.config.get('modules', {}).get('ndr', {}).get('enabled', True):
            self.components['ndr'] = NDRManager(
                config=self.config.get('modules', {}).get('ndr', {})
            )
        
        # Data Loss Prevention (DLP)
        if self.config.get('modules', {}).get('dlp', {}).get('enabled', True):
            self.components['dlp'] = DLPManager(
                config=self.config.get('modules', {}).get('dlp', {})
            )
        
        # File Integrity Monitoring (FIM)
        if self.config.get('modules', {}).get('fim', {}).get('enabled', True):
            self.components['fim'] = FIMManager(
                config=self.config.get('modules', {}).get('fim', {})
            )
        
        # Host-based Intrusion Prevention System (HIPS)
        if self.config.get('modules', {}).get('hips', {}).get('enabled', True):
            self.components['hips'] = HIPSManager(
                config=self.config.get('modules', {}).get('hips', {})
            )
        
        # Network Intrusion Prevention System (NIPS)
        if self.config.get('modules', {}).get('nips', {}).get('enabled', True):
            self.components['nips'] = NIPSManager(
                config=self.config.get('modules', {}).get('nips', {})
            )
        
        # Compliance Manager
        if self.config.get('modules', {}).get('compliance', {}).get('enabled', True):
            self.components['compliance'] = ComplianceManager(
                config=self.config.get('modules', {}).get('compliance', {})
            )
    
    def start(self) -> None:
        """Start all enabled SIEM components."""
        logger.info("Starting SIEM system...")
        
        # Start each component in a separate thread
        for name, component in self.components.items():
            try:
                if hasattr(component, 'start'):
                    logger.info(f"Starting {name}...")
                    component.start()
                    logger.info(f"{name} started successfully")
            except Exception as e:
                logger.error(f"Failed to start {name}: {e}", exc_info=True)
        
        logger.info("SIEM system started successfully")
        
        # Main loop
        try:
            while not self.shutdown_event.is_set():
                # Check component health periodically
                self._check_health()
                self.shutdown_event.wait(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
        except Exception as e:
            logger.critical(f"Unhandled exception in SIEM main loop: {e}", exc_info=True)
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop all SIEM components gracefully."""
        logger.info("Shutting down SIEM system...")
        self.shutdown_event.set()
        
        # Stop components in reverse order
        for name, component in reversed(list(self.components.items())):
            try:
                if hasattr(component, 'stop'):
                    logger.info(f"Stopping {name}...")
                    component.stop()
                    logger.info(f"{name} stopped successfully")
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}", exc_info=True)
        
        logger.info("SIEM system has been shut down")
    
    def _check_health(self) -> None:
        """Check the health of all components and restart if necessary."""
        for name, component in self.components.items():
            try:
                if hasattr(component, 'is_alive') and not component.is_alive():
                    logger.warning(f"Component {name} is not responding, attempting to restart...")
                    if hasattr(component, 'restart'):
                        component.restart()
                    elif hasattr(component, 'start'):
                        component.stop()
                        component.start()
            except Exception as e:
                logger.error(f"Error checking health of {name}: {e}", exc_info=True)
    
    def _handle_shutdown(self, signum, frame) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received shutdown signal {signum}")
        self.shutdown_event.set()


class EventBus:
    """Simple event bus for inter-component communication."""
    
    def __init__(self):
        self.subscribers = {}
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Subscribe to an event type."""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
    
    def publish(self, event_type: str, data: Any = None) -> None:
        """Publish an event to all subscribers."""
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_type}: {e}", exc_info=True)


def main():
    """Main entry point for the SIEM application."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM System')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    args = parser.parse_args()
    
    siem = SIEM(config_path=args.config)
    siem.start()


if __name__ == "__main__":
    main()
