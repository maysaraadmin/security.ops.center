"""
Test script to verify Sysmon integration with SIEM.
This script will:
1. Check if Sysmon is installed and running
2. Generate test events
3. Verify the SIEM can collect these events
"""
import sys
import os
import time
import logging
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.siem.collectors.sysmon_collector import SysmonCollector

def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('sysmon_test.log', encoding='utf-8')
        ]
    )
    return logging.getLogger(__name__)

def check_sysmon_installed(logger):
    """Check if Sysmon is installed and running."""
    try:
        import win32evtlog
        import win32con
        
        # Try to open the Sysmon event log
        h = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        win32evtlog.CloseEventLog(h)
        logger.info("Sysmon is installed and accessible")
        return True
    except Exception as e:
        logger.error(f"Sysmon check failed: {e}")
        logger.error("Please install Sysmon first.")
        logger.error("You can download it from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon")
        return False

def test_sysmon_collector(logger):
    """Test the Sysmon collector."""
    try:
        logger.info("Testing Sysmon collector...")
        collector = SysmonCollector()
        
        try:
            # Get recent events
            logger.info("Collecting Sysmon events...")
            events = collector.get_events(limit=5)
            
            if not events:
                logger.warning("No events found. Please ensure Sysmon is generating events.")
                return False
                
            logger.info(f"Collected {len(events)} events")
            
            # Print a sample event
            logger.info("Sample event:")
            import json
            print(json.dumps(events[0], indent=2))
            
            return True
            
        finally:
            collector.close()
            
    except Exception as e:
        logger.error(f"Error testing Sysmon collector: {e}", exc_info=True)
        return False

def generate_test_events(logger):
    """Generate some test events to verify collection."""
    try:
        import subprocess
        import tempfile
        
        logger.info("Generating test events...")
        
        # Create a temporary file to trigger a file creation event
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp:
            temp.write(b"Test content for SIEM verification")
            temp_path = temp.name
        
        # Run a simple command to generate process creation events
        subprocess.run(["cmd", "/c", "echo", "Generating test event for SIEM"], 
                      capture_output=True, text=True)
        
        # Clean up
        if os.path.exists(temp_path):
            os.unlink(temp_path)
            
        logger.info("Test events generated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error generating test events: {e}", exc_info=True)
        return False

def main():
    """Main function."""
    logger = setup_logging()
    
    logger.info("Starting Sysmon SIEM integration test...")
    
    # Check if Sysmon is installed
    if not check_sysmon_installed(logger):
        return 1
    
    # Generate some test events
    if not generate_test_events(logger):
        logger.warning("Failed to generate test events")
    
    # Test the collector
    if not test_sysmon_collector(logger):
        logger.error("Sysmon collector test failed")
        return 1
    
    logger.info("Sysmon SIEM integration test completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
