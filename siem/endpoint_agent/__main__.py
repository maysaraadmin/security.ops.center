""
SIEM Endpoint Agent
------------------
Main entry point for the SIEM Endpoint Agent.
"""
import os
import sys
import time
import signal
import logging
import argparse
from typing import Optional, Dict, Any

from .agent import SIEMEndpointAgent
from .utils import setup_logging, load_config, is_running_as_admin, ensure_directory_exists

# Configure logging
logger = logging.getLogger('siem_agent')

class SIEMEndpointAgentService:
    """Service wrapper for the SIEM Endpoint Agent."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the SIEM Endpoint Agent service.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.agent = None
        self.running = False
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load the configuration."""
        # Try to find config in standard locations if not specified
        if not self.config_path:
            config_paths = [
                os.path.join(os.getcwd(), 'config.yaml'),
                os.path.join(os.path.dirname(__file__), 'config.yaml'),
                '/etc/siem/endpoint_agent/config.yaml',
                'C:\\ProgramData\\SIEM\\endpoint_agent\\config.yaml',
            ]
            
            for path in config_paths:
                if os.path.exists(path):
                    self.config_path = path
                    logger.info(f"Using configuration file: {path}")
                    break
            else:
                logger.warning("No configuration file found, using defaults")
        
        # Load the configuration
        return load_config(self.config_path)
    
    def _setup_logging(self, config: Dict[str, Any]) -> None:
        """Set up logging based on the configuration."""
        log_config = config.get('logging', {})
        log_level = log_config.get('level', 'INFO')
        log_file = log_config.get('file')
        
        setup_logging(log_level=log_level, log_file=log_file)
    
    def start(self) -> None:
        """Start the SIEM Endpoint Agent service."""
        try:
            # Load configuration
            config = self._load_config()
            
            # Set up logging
            self._setup_logging(config)
            
            logger.info("Starting SIEM Endpoint Agent")
            
            # Check for admin/root privileges if needed
            if config.get('require_admin_privileges', True) and not is_running_as_admin():
                logger.error("This application requires administrator/root privileges to run.")
                sys.exit(1)
            
            # Create necessary directories
            self._create_required_directories(config)
            
            # Initialize and start the agent
            self.agent = SIEMEndpointAgent(config)
            self.agent.start()
            self.running = True
            
            logger.info("SIEM Endpoint Agent started successfully")
            
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
        except Exception as e:
            logger.critical(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the SIEM Endpoint Agent service."""
        if self.running:
            logger.info("Stopping SIEM Endpoint Agent...")
            self.running = False
            
            if self.agent:
                self.agent.stop()
            
            logger.info("SIEM Endpoint Agent stopped")
    
    def _handle_signal(self, signum, frame) -> None:
        """Handle system signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def _create_required_directories(self, config: Dict[str, Any]) -> None:
        """Create required directories specified in the configuration."""
        # Create log directory if log file is specified
        log_config = config.get('logging', {})
        if 'file' in log_config:
            log_dir = os.path.dirname(log_config['file'])
            if log_dir:
                ensure_directory_exists(log_dir)
        
        # Create data directory if specified
        if 'data_dir' in config:
            ensure_directory_exists(config['data_dir'])
        
        # Create cache directory if specified
        if 'cache_dir' in config.get('advanced', {}):
            ensure_directory_exists(config['advanced']['cache_dir'])

def install_service() -> None:
    """Install the SIEM Endpoint Agent as a system service."""
    try:
        if os.name == 'nt':
            _install_windows_service()
        else:
            _install_linux_service()
    except Exception as e:
        logger.error(f"Failed to install service: {e}", exc_info=True)
        sys.exit(1)

def uninstall_service() -> None:
    """Uninstall the SIEM Endpoint Agent system service."""
    try:
        if os.name == 'nt':
            _uninstall_windows_service()
        else:
            _uninstall_linux_service()
    except Exception as e:
        logger.error(f"Failed to uninstall service: {e}", exc_info=True)
        sys.exit(1)

def _install_windows_service() -> None:
    """Install the Windows service."""
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager
        
        # This would typically be in a separate service module
        class SIEMEndpointAgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "SIEMEndpointAgent"
            _svc_display_name_ = "SIEM Endpoint Agent"
            _svc_description_ = "Collects and forwards system logs and security events to a SIEM server"
            
            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                self.agent = None
            
            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                if self.agent:
                    self.agent.stop()
                win32event.SetEvent(self.hWaitStop)
            
            def SvcDoRun(self):
                self.agent = SIEMEndpointAgentService()
                self.agent.start()
        
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SIEMEndpointAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(SIEMEndpointAgentService)
    
    except ImportError:
        logger.error("pywin32 is required to install as a Windows service")
        sys.exit(1)

def _uninstall_windows_service() -> None:
    """Uninstall the Windows service."""
    try:
        import win32serviceutil
        win32serviceutil.RemoveService("SIEMEndpointAgent")
        logger.info("Windows service uninstalled successfully")
    except Exception as e:
        logger.error(f"Failed to uninstall Windows service: {e}")
        raise

def _install_linux_service() -> None:
    """Install the Linux systemd service."""
    try:
        service_content = """[Unit]
Description=SIEM Endpoint Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart={} -m siem.endpoint_agent
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
""".format(sys.executable)
        
        service_path = "/etc/systemd/system/siem-endpoint-agent.service"
        
        # Write the service file
        with open(service_path, 'w') as f:
            f.write(service_content)
        
        # Reload systemd
        os.system('systemctl daemon-reload')
        os.system('systemctl enable siem-endpoint-agent')
        
        logger.info("Linux service installed successfully")
        logger.info("Start the service with: systemctl start siem-endpoint-agent")
    
    except Exception as e:
        logger.error(f"Failed to install Linux service: {e}")
        raise

def _uninstall_linux_service() -> None:
    """Uninstall the Linux systemd service."""
    try:
        service_path = "/etc/systemd/system/siem-endpoint-agent.service"
        
        if os.path.exists(service_path):
            # Stop and disable the service
            os.system('systemctl stop siem-endpoint-agent')
            os.system('systemctl disable siem-endpoint-agent')
            
            # Remove the service file
            os.remove(service_path)
            
            # Reload systemd
            os.system('systemctl daemon-reload')
            
            logger.info("Linux service uninstalled successfully")
        else:
            logger.warning("Service file not found, nothing to uninstall")
    
    except Exception as e:
        logger.error(f"Failed to uninstall Linux service: {e}")
        raise

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SIEM Endpoint Agent')
    
    # Main arguments
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    
    # Service management
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument('--install', action='store_true', help='Install as a system service')
    service_group.add_argument('--uninstall', action='store_true', help='Uninstall the system service')
    service_group.add_argument('--start', action='store_true', help='Start the service')
    service_group.add_argument('--stop', action='store_true', help='Stop the service')
    service_group.add_argument('--restart', action='store_true', help='Restart the service')
    service_group.add_argument('--status', action='store_true', help='Check service status')
    
    # Additional options
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    return parser.parse_args()

def main() -> None:
    """Main entry point for the SIEM Endpoint Agent."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Handle version request
    if args.version:
        from . import __version__
        print(f"SIEM Endpoint Agent v{__version__}")
        sys.exit(0)
    
    # Handle service management commands
    if args.install:
        install_service()
        sys.exit(0)
    elif args.uninstall:
        uninstall_service()
        sys.exit(0)
    
    # Start the agent
    service = SIEMEndpointAgentService(config_path=args.config)
    
    if args.start:
        logger.info("Starting SIEM Endpoint Agent...")
        service.start()
    elif args.stop:
        logger.info("Stopping SIEM Endpoint Agent...")
        service.stop()
    elif args.restart:
        logger.info("Restarting SIEM Endpoint Agent...")
        service.stop()
        service.start()
    elif args.status:
        # Simple status check
        if service.running:
            print("SIEM Endpoint Agent is running")
            sys.exit(0)
        else:
            print("SIEM Endpoint Agent is not running")
            sys.exit(1)
    else:
        # Run in the foreground
        service.start()

if __name__ == "__main__":
    main()
