"""
Simplified SIEM implementation with enhanced configuration and logging.
"""

import os
import sys
import yaml
import logging
import signal
import threading
import logging.handlers
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Type, TypeVar, Callable

# Type variable for component classes
T = TypeVar('T')

class Config:
    """Configuration manager for the SIEM."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize with optional configuration dictionary."""
        self._config = config or {}
        self._defaults = {
            'logging': {
                'level': 'INFO',
                'console': {
                    'enabled': True,
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'file': {
                    'enabled': False,
                    'level': 'DEBUG',
                    'path': 'logs/siem.log',
                    'max_size': 10,  # MB
                    'backup_count': 5,
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            },
            'components': {
                'enabled': [],
                'log_collector': {
                    'enabled': False,
                    'paths': ['/var/log']
                },
                'correlation_engine': {
                    'enabled': False,
                    'rules_path': 'config/correlation_rules'
                }
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    return default
            return value
        except (KeyError, TypeError):
            # Try to get from defaults
            default_value = self._get_default(key)
            return default if default_value is None else default_value
    
    def _get_default(self, key: str) -> Any:
        """Get default value for a key."""
        keys = key.split('.')
        value = self._defaults
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return None
    
    def get_component_config(self, component: str) -> Dict[str, Any]:
        """Get configuration for a specific component."""
        component_config = self.get(f'components.{component}', {})
        if not isinstance(component_config, dict):
            return {'enabled': False}
        return component_config
    
    def to_dict(self) -> Dict[str, Any]:
        """Return the configuration as a dictionary."""
        return self._config


class EventBus:
    """Simple event bus for inter-component communication."""
    
    def __init__(self):
        """Initialize the event bus."""
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
                    logging.error(f"Error in event handler for {event_type}: {e}")


class SimpleSIEM:
    """A simplified SIEM implementation with enhanced configuration."""
    
    def __init__(self, config: Optional[Union[Dict[str, Any], str]] = None):
        """Initialize the SimpleSIEM with configuration.
        
        Args:
            config: Either a configuration dictionary or a path to a YAML config file.
        """
        # Initialize basic attributes
        self.running = False
        self.shutdown_event = threading.Event()
        self.components = {}
        self.event_bus = EventBus()
        
        # Load configuration
        self.config = self._load_config(config)
        
        # Set up logging
        self._setup_logging()
        
        # Get logger after logging is set up
        self.logger = logging.getLogger('siem.core')
        self.logger.info("Initializing SimpleSIEM...")
        
        # Initialize components
        self._init_components()
    
    def _load_config(self, config: Optional[Union[Dict[str, Any], str]]) -> Config:
        """Load configuration from dict or file."""
        if isinstance(config, str):
            # Load from file
            try:
                with open(config, 'r') as f:
                    config_dict = yaml.safe_load(f) or {}
                return Config(config_dict)
            except Exception as e:
                print(f"Error loading config file: {e}", file=sys.stderr)
                return Config()
        else:
            return Config(config or {})
    
    def _setup_logging(self) -> None:
        """Set up logging based on configuration."""
        # Get root logger
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)  # Set root to lowest level
        
        # Clear existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Console handler
        if self.config.get('logging.console.enabled', True):
            console_level = self._get_log_level(
                self.config.get('logging.console.level'),
                self.config.get('logging.level', 'INFO')
            )
            
            console_handler = logging.StreamHandler()
            console_handler.setLevel(console_level)
            console_format = logging.Formatter(
                self.config.get('logging.console.format')
            )
            console_handler.setFormatter(console_format)
            logger.addHandler(console_handler)
        
        # File handler
        if self.config.get('logging.file.enabled', False):
            file_level = self._get_log_level(
                self.config.get('logging.file.level'),
                self.config.get('logging.level', 'DEBUG')
            )
            
            log_file = self.config.get('logging.file.path')
            log_dir = os.path.dirname(log_file)
            
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_file,
                maxBytes=self.config.get('logging.file.max_size', 10) * 1024 * 1024,  # MB to bytes
                backupCount=self.config.get('logging.file.backup_count', 5)
            )
            file_handler.setLevel(file_level)
            file_format = logging.Formatter(
                self.config.get('logging.file.format')
            )
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
    
    def _get_log_level(self, level_str: Optional[str], default: str = 'INFO') -> int:
        """Convert log level string to logging constant."""
        level_str = (level_str or default).upper()
        return getattr(logging, level_str, logging.INFO)
    
    def _init_components(self) -> None:
        """Initialize enabled components."""
        enabled_components = self.config.get('components.enabled', [])
        
        # Initialize component registry
        self._component_registry = {
            'log_collector': self._init_log_collector,
            'dummy_component': self._init_dummy_component
        }
        
        for component_name in enabled_components:
            self.logger.info(f"Initializing component: {component_name}")
            try:
                if component_name in self._component_registry:
                    # Initialize the component using its factory function
                    component = self._component_registry[component_name]()
                    if component:
                        self.components[component_name] = component
                        self.logger.info(f"Successfully initialized component: {component_name}")
                    else:
                        self.logger.error(f"Failed to initialize component: {component_name}")
                else:
                    self.logger.warning(f"Unknown component: {component_name}")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize {component_name}: {e}", exc_info=True)
                self.components[component_name] = {
                    'initialized': False,
                    'error': str(e)
                }
    
    def _init_dummy_component(self):
        """Initialize the Dummy component."""
        try:
            from src.siem.core.components.dummy_component import create_component
            
            # Get component-specific config
            component_config = self.config.get_component_config('dummy_component')
            
            # Create and return the component
            return create_component(component_config)
            
        except ImportError as e:
            self.logger.error(f"Failed to import dummy component: {e}", exc_info=True)
            return None
    
    def _init_log_collector(self):
        """Initialize the LogCollector component."""
        from src.siem.components.log_collector import create_component
        
        # Get component-specific config
        component_config = self.config.get_component_config('log_collector')
        
        if not component_config.get('enabled', False):
            self.logger.info("LogCollector is disabled in configuration")
            return None
            
        try:
            # Create and return the component
            return create_component(component_config, self.event_bus)
        except Exception as e:
            self.logger.error(f"Failed to initialize LogCollector: {e}", exc_info=True)
            return None
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers in the main thread."""
        # Only set up signal handlers in the main thread
        if threading.current_thread() is threading.main_thread():
            self.logger.debug("Setting up signal handlers in main thread")
            signal.signal(signal.SIGINT, self._handle_shutdown)
            signal.signal(signal.SIGTERM, self._handle_shutdown)
        else:
            self.logger.debug("Not in main thread, skipping signal handler setup")
    
    def start(self) -> None:
        """Start the SIEM and all enabled components."""
        if self.running:
            self.logger.warning("SIEM is already running")
            return
        
        self.logger.info("Starting SimpleSIEM...")
        self.running = True
        
        # Set up signal handlers
        self._setup_signal_handlers()
        
        # Start components
        for name, component in self.components.items():
            if component.get('enabled', False) and hasattr(component, 'start'):
                try:
                    self.logger.info(f"Starting component: {name}")
                    component.start()
                except Exception as e:
                    self.logger.error(f"Error starting component {name}: {e}")
        
        self.logger.info("SimpleSIEM started successfully")
        
        # Keep the main thread alive
        try:
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested via keyboard interrupt")
            self.stop()
    
    def stop(self) -> None:
        """Stop the SIEM and all components."""
        if not self.running:
            return
        
        self.logger.info("Stopping SimpleSIEM...")
        
        # Stop components
        for name, component in self.components.items():
            if hasattr(component, 'stop'):
                try:
                    self.logger.info(f"Stopping component: {name}")
                    component.stop()
                except Exception as e:
                    self.logger.error(f"Error stopping component {name}: {e}")
        
        self.shutdown_event.set()
        self.running = False
        self.logger.info("SimpleSIEM stopped")
    
    def _handle_shutdown(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()


def main():
    """Run the SimpleSIEM with example configuration."""
    # Example configuration
    config = {
        'logging': {
            'level': 'DEBUG',
            'console': {
                'enabled': True,
                'level': 'DEBUG'
            },
            'file': {
                'enabled': True,
                'path': 'logs/siem.log',
                'max_size': 10,  # MB
                'backup_count': 5
            }
        },
        'components': {
            'enabled': ['dummy_component']
        }
    }
    
    # Create and start the SIEM
    siem = SimpleSIEM(config)
    
    try:
        siem.start()
    except KeyboardInterrupt:
        siem.stop()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
