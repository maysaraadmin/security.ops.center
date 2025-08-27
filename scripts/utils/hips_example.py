"""
HIPS Example - Demonstrates the Host-based Intrusion Prevention System.
"""
import os
import sys
import time
import logging
from pathlib import Path

# Add the parent directory to the path so we can import the hips module
sys.path.append(str(Path(__file__).parent.parent))

from src.hips.manager import HIPSManager

def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('hips_example.log')
        ]
    )

def alert_callback(alert):
    """Callback function for handling alerts."""
    print(f"\n=== ALERT ===")
    print(f"Rule: {alert.get('rule_name')}")
    print(f"Severity: {alert.get('severity').upper()}")
    print(f"Description: {alert.get('description')}")
    print(f"Details: {alert.get('details', 'No additional details')}")
    print("============\n")

def main():
    """Main function to demonstrate HIPS functionality."""
    # Set up logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting HIPS example...")
        
        # Create a HIPS manager with the default configuration directory
        hips_manager = HIPSManager(alert_callback=alert_callback)
        
        # Enable all monitoring types
        hips_manager.set_monitoring('file_system', True)
        hips_manager.set_monitoring('registry', True)
        hips_manager.set_monitoring('processes', True)
        hips_manager.set_monitoring('network', True)
        hips_manager.set_monitoring('services', True)
        
        # Start the HIPS manager
        if not hips_manager.start():
            logger.error("Failed to start HIPS manager")
            return 1
        
        logger.info("HIPS manager started. Monitoring for suspicious activities...")
        logger.info("Press Ctrl+C to stop")
        
        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping HIPS manager...")
        
        # Stop the HIPS manager
        hips_manager.stop()
        logger.info("HIPS manager stopped")
        
        return 0
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
