"""
EDR and SIEM Services Launcher

This script starts both the EDR and SIEM services together with proper error handling
and cleanup.
"""
import sys
import os
import time
import signal
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import launchers
try:
    from src.edr.launcher import EDRLauncher
    from src.siem.launcher import SIEMLauncher
except ImportError as e:
    print(f"Error importing launchers: {e}")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('service_launcher')

class ServiceManager:
    """Manages EDR and SIEM services."""
    
    def __init__(self, edr_config: Optional[Dict[str, Any]] = None, 
                 siem_config: Optional[Dict[str, Any]] = None):
        """Initialize the service manager.
        
        Args:
            edr_config: Optional EDR configuration overrides
            siem_config: Optional SIEM configuration overrides
        """
        self.edr_launcher = EDRLauncher(edr_config or {})
        self.siem_launcher = SIEMLauncher(siem_config or {})
        self._running = False
        self._shutdown_event = threading.Event()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signal.Signals(signum).name}, shutting down...")
        self._shutdown_event.set()
    
    def start(self) -> bool:
        """Start all services."""
        if self._running:
            logger.warning("Services are already running")
            return True
            
        logger.info("Starting EDR and SIEM services...")
        
        try:
            # Initialize services
            if not self.edr_launcher.initialize():
                logger.error("Failed to initialize EDR service")
                return False
                
            if not self.siem_launcher.initialize():
                logger.error("Failed to initialize SIEM service")
                return False
            
            # Start services
            self.edr_launcher.start()
            self.siem_launcher.start()
            
            self._running = True
            logger.info("All services started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start services: {e}", exc_info=True)
            self.stop()
            return False
    
    def stop(self):
        """Stop all services."""
        logger.info("Stopping services...")
        
        try:
            if hasattr(self.siem_launcher, 'stop'):
                self.siem_launcher.stop()
        except Exception as e:
            logger.error(f"Error stopping SIEM service: {e}", exc_info=True)
            
        try:
            if hasattr(self.edr_launcher, 'stop'):
                self.edr_launcher.stop()
        except Exception as e:
            logger.error(f"Error stopping EDR service: {e}", exc_info=True)
        
        self._running = False
        logger.info("All services stopped")
    
    def run(self):
        """Run services until shutdown signal is received."""
        if not self.start():
            return False
        
        try:
            # Keep the main thread alive
            while not self._shutdown_event.is_set():
                time.sleep(1)
                
                # Check if services are still running
                if not self._check_services():
                    logger.error("One or more services have stopped unexpectedly")
                    break
            
            return True
            
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return False
            
        finally:
            self.stop()
    
    def _check_services(self) -> bool:
        """Check if all services are still running."""
        # Add service-specific health checks here if needed
        return True

def main():
    """Main entry point."""
    # You can load configurations from files here if needed
    manager = ServiceManager()
    
    if not manager.run():
        logger.error("Failed to run services")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
