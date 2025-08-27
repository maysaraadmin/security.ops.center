#!/usr/bin/env python3
"""
Security Operations Center (SOC) - Main Entry Point

This is the main entry point for the Security Operations Center application.
It initializes and starts all core services including SIEM, NIPS, and other security modules.
"""

import os
import sys
import logging
import signal
import threading
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('soc.log')
    ]
)
logger = logging.getLogger('soc')

# Import core components
from src.siem.core.siem import SIEM
from src.nips.manager import NIPSManager
from src.edr.server import EDRAgentServer
from src.compliance.manager import ComplianceManager

class SecurityOperationsCenter:
    """Main class for the Security Operations Center application."""
    
    def __init__(self):
        """Initialize the SOC application."""
        self.siem = None
        self.nips = None
        self.edr_server = None
        self.compliance_manager = None
        self.shutdown_event = threading.Event()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def initialize(self):
        """Initialize all SOC components."""
        logger.info("Initializing Security Operations Center...")
        
        try:
            # Initialize SIEM
            logger.info("Initializing SIEM...")
            self.siem = SIEM()
            
            # Initialize NIPS (Network Intrusion Prevention System)
            logger.info("Initializing NIPS...")
            self.nips = NIPSManager()
            
            # Initialize EDR (Endpoint Detection and Response)
            logger.info("Initializing EDR Server...")
            self.edr_server = EDRAgentServer()
            
            # Initialize Compliance Manager
            logger.info("Initializing Compliance Manager...")
            self.compliance_manager = ComplianceManager()
            
            logger.info("All components initialized successfully.")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize SOC components: {e}", exc_info=True)
            return False
    
    def start(self):
        """Start all SOC components."""
        if not self.siem or not self.nips or not self.edr_server or not self.compliance_manager:
            logger.error("Cannot start SOC: Components not initialized")
            return False
        
        try:
            logger.info("Starting Security Operations Center...")
            
            # Start SIEM
            logger.info("Starting SIEM...")
            self.siem.start()
            
            # Start NIPS
            logger.info("Starting NIPS...")
            self.nips.start()
            
            # Start EDR Server
            logger.info("Starting EDR Server...")
            self.edr_server.start()
            
            # Start Compliance Manager
            logger.info("Starting Compliance Manager...")
            self.compliance_manager.start()
            
            logger.info("Security Operations Center is now running. Press Ctrl+C to stop.")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start SOC: {e}", exc_info=True)
            return False
    
    def stop(self):
        """Stop all SOC components gracefully."""
        logger.info("Shutting down Security Operations Center...")
        
        try:
            if self.compliance_manager:
                logger.info("Stopping Compliance Manager...")
                self.compliance_manager.stop()
                
            if self.edr_server:
                logger.info("Stopping EDR Server...")
                self.edr_server.stop()
                
            if self.nips:
                logger.info("Stopping NIPS...")
                self.nips.stop()
                
            if self.siem:
                logger.info("Stopping SIEM...")
                self.siem.stop()
                
            logger.info("Security Operations Center has been shut down.")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
        finally:
            self.shutdown_event.set()
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received shutdown signal {signum}")
        self.stop()

def main():
    """Main entry point for the SOC application."""
    # Ensure the data directory exists
    data_dir = os.path.join(project_root, 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Set environment variables
    os.environ['SIEM_DB_PATH'] = os.path.join(data_dir, 'siem.db')
    
    # Create and start the SOC
    soc = SecurityOperationsCenter()
    
    if not soc.initialize():
        logger.error("Failed to initialize SOC components. Exiting...")
        return 1
    
    if not soc.start():
        logger.error("Failed to start SOC. Exiting...")
        return 1
    
    # Keep the main thread alive
    try:
        soc.shutdown_event.wait()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt. Shutting down...")
        soc.stop()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
