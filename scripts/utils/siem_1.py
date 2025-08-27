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
from src.siem.core.log_collector import LogCollector
from src.siem.core.correlation_engine import CorrelationEngine
from src.edr.server import EDRAgentServer
from src.ndr.manager import NDRManager
from src.dlp.manager import DLPManager
from src.fim.manager import FIMManager
from src.hips.manager import HIPSManager
from src.nips.manager import NIPSManager
from src.siem.services.monitoring_service import create_monitoring_service
from src.compliance.manager import ComplianceManager

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
    
    def __init__(self, config=None):
        """Initialize the SIEM with configuration.
        
        Args:
            config: Either a path to a YAML config file or a config dictionary.
        """
        # Initialize logging first
        self.logger = logging.getLogger('siem.core')
        self.logger.info("Starting SIEM initialization...")
        
        # Initialize components with default values
        self.event_bus = None
        self.log_collector = None
        self.correlation_engine = None
        self.edr_server = None
        self.ndr_manager = None
        self.dlp_manager = None
        self.fim_manager = None
        self.hips_manager = None
        self.nips_manager = None
        self.compliance_manager = None
        self.monitoring_service = None
        self.shutdown_event = None
        
        try:
            # Load configuration
            self.logger.debug(f"Processing config of type: {type(config)}")
            if isinstance(config, dict):
                self.logger.debug("Expanding environment variables in config")
                self.config = self._expand_env_vars(config)
            elif isinstance(config, str):
                self.logger.info(f"Loading config from file: {config}")
                self.config = self._load_config(config)
            else:
                self.logger.warning("No configuration provided, using defaults")
                self.config = {}
            
            # Set up logging with config
            self.logger.debug("Setting up logging...")
            self._setup_logging()
            
            # Initialize event bus and shutdown event
            self.event_bus = EventBus()
            self.shutdown_event = threading.Event()
            
            # Register signal handlers
            signal.signal(signal.SIGINT, self._handle_shutdown)
            signal.signal(signal.SIGTERM, self._handle_shutdown)
            
            # Log successful initialization
            self.logger.info("SIEM core configuration loaded successfully")
            
            # Initialize components
            self._init_components()
            self.logger.info("SIEM initialization complete")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SIEM: {e}", exc_info=True)
            raise
    
    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration from file."""
        self.logger.debug(f"_load_config called with config_path: {config_path}")
        
        if not config_path:
            # Default config path
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'config',
                'siem_config.yaml'
            )
            self.logger.debug(f"No config path provided, using default: {config_path}")
        
        try:
            # Check if file exists
            if not os.path.exists(config_path):
                self.logger.warning(f"Config file not found at {config_path}, using empty config")
                return {}
                
            self.logger.debug(f"Loading config from: {os.path.abspath(config_path)}")
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                self.logger.debug(f"Raw config loaded: {config}")
                
                # Expand environment variables in config
                config = self._expand_env_vars(config)
                self.logger.debug(f"Config after env var expansion: {config}")
                
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
    
    def _init_monitoring(self) -> None:
        """Initialize monitoring service."""
        monitoring_config = self.config.get('monitoring', {})
        
        # Load monitoring config from file if specified
        if 'config_file' in monitoring_config:
            config_path = Path(monitoring_config['config_file'])
            if config_path.exists():
                with open(config_path, 'r') as f:
                    monitoring_config = yaml.safe_load(f)
        
        # Initialize monitoring service
        self.monitoring_service = create_monitoring_service(monitoring_config)
        self.monitoring_service.start()
        
        logger.info("Monitoring service initialized")
    
    def _init_components(self) -> None:
        """Initialize all SIEM components."""
        # Initialize monitoring service first if enabled
        if self.config.get('monitoring', {}).get('enabled', False):
            self.monitoring_service = create_monitoring_service(
                self.config.get('monitoring', {})
            )
        else:
            self.logger.info("Monitoring service is disabled")
        
        # Initialize log collector if enabled
        if self.config.get('log_collector', {}).get('enabled', False):
            self.log_collector = LogCollector(self.config.get('log_collector', {}))
            self.logger.info("Log collector initialized")
        else:
            self.logger.info("Log collector is disabled")
        
        # Initialize correlation engine if enabled
        if self.config.get('correlation', {}).get('enabled', False):
            self.correlation_engine = CorrelationEngine(
                self.config.get('correlation', {}),
                event_bus=self.event_bus
            )
            self.logger.info("Correlation engine initialized")
        else:
            self.logger.info("Correlation engine is disabled")
        
        # Initialize EDR server if enabled
        if self.config.get('edr', {}).get('enabled', False):
            self.edr_server = EDRAgentServer(
                self.config['edr'],
                event_bus=self.event_bus
            )
            self.logger.info("EDR server initialized")
        else:
            self.logger.info("EDR server is disabled")
        
        # Initialize other managers if enabled
        if self.config.get('ndr', {}).get('enabled', False):
            self.ndr_manager = NDRManager(self.config.get('ndr', {}))
            self.logger.info("NDR manager initialized")
        else:
            self.logger.info("NDR manager is disabled")
            
        if self.config.get('dlp', {}).get('enabled', False):
            self.dlp_manager = DLPManager(self.config.get('dlp', {}))
            self.logger.info("DLP manager initialized")
        else:
            self.logger.info("DLP manager is disabled")
            
        if self.config.get('fim', {}).get('enabled', False):
            self.fim_manager = FIMManager(self.config.get('fim', {}))
            self.logger.info("FIM manager initialized")
        else:
            self.logger.info("FIM manager is disabled")
            
        if self.config.get('hips', {}).get('enabled', False):
            self.hips_manager = HIPSManager(self.config.get('hips', {}))
            self.logger.info("HIPS manager initialized")
        else:
            self.logger.info("HIPS manager is disabled")
            
        if self.config.get('nips', {}).get('enabled', False):
            self.nips_manager = NIPSManager(self.config.get('nips', {}))
            self.logger.info("NIPS manager initialized")
        else:
            self.logger.info("NIPS manager is disabled")
        
        # Initialize compliance manager if enabled
        if self.config.get('compliance', {}).get('enabled', False):
            self.compliance_manager = ComplianceManager(
                self.config.get('compliance', {})
            )
            self.logger.info("Compliance manager initialized")
        else:
            self.logger.info("Compliance manager is disabled")
        
        # Register component metrics with monitoring service if enabled
        if self.monitoring_service:
            self._register_component_metrics()
    
    def _register_component_metrics(self) -> None:
        """Register component metrics with monitoring service."""
        # Register log collector metrics
        if self.log_collector:
            self.monitoring_service.register_metrics(self.log_collector.get_metrics())
        
        # Register correlation engine metrics
        if self.correlation_engine:
            self.monitoring_service.register_metrics(self.correlation_engine.get_metrics())
        
        # Register EDR server metrics
        if self.edr_server:
            self.monitoring_service.register_metrics(self.edr_server.get_metrics())
        
        # Register other manager metrics
        if self.ndr_manager:
            self.monitoring_service.register_metrics(self.ndr_manager.get_metrics())
        if self.dlp_manager:
            self.monitoring_service.register_metrics(self.dlp_manager.get_metrics())
        if self.fim_manager:
            self.monitoring_service.register_metrics(self.fim_manager.get_metrics())
        if self.hips_manager:
            self.monitoring_service.register_metrics(self.hips_manager.get_metrics())
        if self.nips_manager:
            self.monitoring_service.register_metrics(self.nips_manager.get_metrics())
        
        # Register compliance manager metrics
        if self.compliance_manager:
            self.monitoring_service.register_metrics(self.compliance_manager.get_metrics())
    
    def _start_components(self) -> None:
        """Start all SIEM components."""
        # Start log collector
        if self.log_collector:
            self.log_collector.start()
        
        # Start correlation engine
        if self.correlation_engine:
            self.correlation_engine.start()
        
        # Start EDR server
        if self.edr_server:
            self.edr_server.start()
        
        # Start other managers
        if self.ndr_manager:
            self.ndr_manager.start()
        if self.dlp_manager:
            self.dlp_manager.start()
        if self.fim_manager:
            self.fim_manager.start()
        if self.hips_manager:
            self.hips_manager.start()
        if self.nips_manager:
            self.nips_manager.start()
        
        # Start compliance manager
        if self.compliance_manager:
            self.compliance_manager.start()
    
    def start(self) -> None:
        """Start all SIEM components."""
        try:
            logger.info("Starting SIEM...")
            
            # Initialize monitoring first
            self._init_monitoring()
            
            # Initialize and start other components
            self._init_components()
            self._start_components()
            
            logger.info("SIEM started successfully")
            
            # Keep the main thread alive
            signal.signal(signal.SIGINT, self._handle_shutdown)
            signal.signal(signal.SIGTERM, self._handle_shutdown)
            
            while True:
                time.sleep(1)
                
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
