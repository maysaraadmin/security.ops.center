"""
SIEM Component Launcher

This module provides a launcher for the SIEM component with enhanced error handling
and configuration management.
"""

import logging
import os
import sys
import signal
import traceback
import threading
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional, Type, TypeVar, Callable
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.base_launcher import BaseLauncher
from .config import load_config, SIEMConfig, DatabaseConfig, LoggingConfig
from .health import HealthChecker, HealthStatus

# Type variable for generic return types
T = TypeVar('T')

class SIEMError(Exception):
    """Base exception for SIEM launcher errors."""
    pass

class ConfigurationError(SIEMError):
    """Raised when there is an error in the configuration."""
    pass

class InitializationError(SIEMError):
    """Raised when there is an error initializing the SIEM component."""
    pass

class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health check endpoints."""
    
    def __init__(self, health_checker: HealthChecker, *args, **kwargs):
        self.health_checker = health_checker
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests to the health check endpoint."""
        try:
            if self.path == '/health' or self.path == '/health/':
                self._handle_health_check()
            elif self.path == '/health/detailed' or self.path.startswith('/health/'):
                self._handle_detailed_health()
            else:
                self.send_error(404, f"Endpoint {self.path} not found")
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def _handle_health_check(self):
        """Handle basic health check endpoint."""
        status = self.health_checker.get_status()
        
        if status == HealthStatus.HEALTHY:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'healthy',
                'timestamp': time.time(),
            }).encode())
        else:
            self.send_response(503 if status == HealthStatus.UNHEALTHY else 206)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'unhealthy' if status == HealthStatus.UNHEALTHY else 'degraded',
                'message': 'Service is not healthy',
                'timestamp': time.time(),
            }).encode())
    
    def _handle_detailed_health(self):
        """Handle detailed health check endpoint."""
        results = self.health_checker.results
        status = self.health_checker.get_status()
        
        response = {
            'status': status.name.lower(),
            'timestamp': time.time(),
            'checks': {}
        }
        
        for name, result in results.items():
            response['checks'][name] = {
                'status': result.status.name.lower(),
                'message': result.message,
                'timestamp': result.timestamp.isoformat(),
                'details': result.details
            }
        
        self.send_response(200 if status == HealthStatus.HEALTHY else 503)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, default=str).encode())
    
    def log_message(self, format, *args):
        """Override to use the logger instead of stderr."""
        self.logger.info(format % args)


class HealthCheckServer:
    """Simple HTTP server for health check endpoints."""
    
    def __init__(self, health_checker: HealthChecker, host: str = '0.0.0.0', port: int = 8080):
        self.health_checker = health_checker
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.logger = logging.getLogger('siem.health.server')
    
    def start(self):
        """Start the health check server in a background thread."""
        if self.server is not None:
            self.logger.warning("Health check server is already running")
            return
            
        def run():
            handler = lambda *args: HealthCheckHandler(self.health_checker, *args)
            self.server = HTTPServer((self.host, self.port), handler)
            self.logger.info(f"Health check server started on http://{self.host}:{self.port}")
            self.server.serve_forever()
        
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the health check server."""
        if self.server:
            self.logger.info("Shutting down health check server")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            if self.thread:
                self.thread.join(timeout=5)
                self.thread = None


class SIEMLauncher(BaseLauncher):
    """Launcher for the SIEM component with enhanced error handling and configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the SIEM launcher with configuration.
        
        Args:
            config_path: Path to the configuration file. If not provided, uses default.
            
        Raises:
            ConfigurationError: If the configuration is invalid or missing required values.
        """
        try:
            # Load and validate configuration
            self.config = self._load_config(config_path)
            
            # Set up logging early
            self._setup_logging()
            
            # Initialize base launcher with validated config
            super().__init__(self.config.dict())
            
            # Initialize SIEM instance
            self.siem = None
            self._running = False
            self._health_checker = None
            self._health_server = None
            
            # Set up health monitoring if enabled
            if self.config.get('health_check', {}).get('enabled', True):
                self._setup_health_monitoring()
            
            # Set up signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
            self.logger.info("SIEM launcher initialized successfully")
            
        except Exception as e:
            # Log the error before re-raising
            if 'logger' in self.__dict__:
                self.logger.critical(f"Failed to initialize SIEM launcher: {str(e)}", 
                                   exc_info=True)
            raise InitializationError(f"Failed to initialize SIEM: {str(e)}") from e
    
    def _load_config(self, config_path: Optional[str] = None) -> SIEMConfig:
        """Load and validate configuration.
        
        Args:
            config_path: Path to the configuration file.
            
        Returns:
            SIEMConfig: Validated configuration object.
            
        Raises:
            ConfigurationError: If the configuration is invalid.
        """
        try:
            return load_config(config_path)
        except Exception as e:
            raise ConfigurationError(f"Configuration error: {str(e)}") from e
    
    def _setup_logging(self) -> None:
        """Set up logging based on configuration."""
        log_config = self.config.logging
        
        # Configure root logger
        logging.basicConfig(
            level=log_config.level,
            format=log_config.format,
            handlers=[
                logging.StreamHandler(),
                logging.handlers.RotatingFileHandler(
                    log_config.file,
                    maxBytes=log_config.max_size * 1024 * 1024,  # Convert MB to bytes
                    backupCount=log_config.backup_count
                )
            ]
        )
        
        self.logger = logging.getLogger('siem.launcher')
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
        
    def initialize(self) -> bool:
        """Initialize the SIEM component.
        
        Returns:
            bool: True if initialization was successful, False otherwise.
            
        Raises:
            InitializationError: If initialization fails.
        """
        self.logger.info("Starting SIEM component initialization...")
        
        if self._running:
            self.logger.warning("SIEM is already running")
            return True
            
        try:
            # Validate configuration
            if not self.config:
                raise InitializationError("No configuration provided")
            siem_config = self.config.get('siem', {})
            self.logger.debug(f"Raw SIEM config: {siem_config}")
            
            # Set up default configuration if not provided
            if not siem_config:
                self.logger.warning("No SIEM configuration found, using defaults")
                siem_config = {
                    'logging': {
                        'level': 'INFO',
                        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        'file': 'logs/siem.log'
                    },
                    'components': {
                        'log_collector': {'enabled': True},
                        'correlation_engine': {'enabled': True},
                        'compliance': {'enabled': True}
                    }
                }
                self.logger.debug(f"Using default config: {siem_config}")
            
            # Ensure logs directory exists
            log_config = siem_config.get('logging', {})
            file_config = log_config.get('file', {})
            
            # Get log file path from config or use default
            if isinstance(file_config, dict) and file_config.get('enabled', False):
                log_file = file_config.get('path', 'logs/siem.log')
                log_dir = os.path.dirname(log_file)
                if log_dir:  # Only create directory if a path is specified
                    os.makedirs(log_dir, exist_ok=True)
                    self.logger.debug(f"Created log directory: {os.path.abspath(log_dir)}")
            
            # Import SIEM class
            self.logger.info("Importing SIEM module...")
            try:
                from src.siem.core.siem import SIEM
                self.logger.info("Successfully imported SIEM module")
            except ImportError as ie:
                self.logger.error(f"Failed to import SIEM module: {ie}")
                import traceback
                self.logger.error(traceback.format_exc())
                return False
            
            # Initialize SIEM with config
            self.logger.info("Initializing SIEM component...")
            try:
                self.siem = SIEM(siem_config)
                self.logger.info("SIEM component initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize SIEM: {e}", exc_info=True)
                return False
            
            self.logger.info("✅ SIEM component initialized successfully")
            return True
            
        except ImportError as ie:
            self.logger.error(f"Failed to import SIEM module: {ie}", exc_info=True)
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SIEM component: {e}", exc_info=True)
            return False
    
    def start(self) -> None:
        """Start the SIEM component."""
        if not self.siem:
            self.logger.error("SIEM component not initialized")
            return
            
        try:
            self.siem.start()
            self._running = True
            self.logger.info("SIEM component started")
        except Exception as e:
            self.logger.error(f"Failed to start SIEM component: {e}", exc_info=True)
            raise
    
    def stop(self) -> None:
        """Stop the SIEM component and all services."""
        self.logger.info("Initiating SIEM shutdown...")
        
        # Stop health monitoring
        if self._health_checker:
            self.logger.debug("Stopping health checker...")
            self._health_checker.stop()
            
        # Stop health server if running
        if self._health_server:
            self.logger.debug("Stopping health check server...")
            self._health_server.stop()
        
        # Stop SIEM component
        if self.siem:
            self.logger.info("Stopping SIEM component...")
            try:
                self.siem.stop()
            except Exception as e:
                self.logger.error(f"Error stopping SIEM component: {e}", exc_info=True)
        
        self._running = False
        self.logger.info("SIEM shutdown complete")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the SIEM component."""
        if not self.siem:
            return {"status": "not_initialized"}
            
        try:
            return {
                "status": "running" if self._running else "stopped",
                "component": "siem",
                "details": self.siem.get_status() if hasattr(self.siem, 'get_status') else {}
            }
        except Exception as e:
            self.logger.error(f"Error getting SIEM status: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

def run_siem(config_path: Optional[str] = None):
    """Run the SIEM component.
    
    Args:
        config_path: Path to the configuration file.
        
    Returns:
        bool: True if the SIEM started successfully, False otherwise.
    """
    import yaml
    import os
    
    # Set up basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('siem_launcher.log')
        ]
    )
    logger = logging.getLogger('siem_launcher')
    
    # Load configuration
    config = {}
    if config_path:
        try:
            if not os.path.exists(config_path):
                logger.warning(f"Config file not found at {config_path}, using defaults")
            else:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
                    logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}", exc_info=True)
            return False
    
    # Configure logging
    log_config = config.get('logging', {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'siem.log'
    })
    
    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', 'siem.log'))
        ]
    )
    
    # Create and run the launcher
    launcher = SIEMLauncher(config)
    return launcher.run()

if __name__ == "__main__":
    import sys
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(0 if run_siem(config_path) else 1)
