#!/usr/bin/env python3
"""
SIEM Component Test

This script tests the SIEM component with proper error handling and logging.
"""

import os
import sys
import logging
import time
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_test.log')
    ]
)
logger = logging.getLogger('siem_test')

def test_siem_component():
    """Test the SIEM component with proper error handling."""
    try:
        logger.info("Starting SIEM component test...")
        
        # Try to import the SIEM component
        try:
            from src.siem.core.siem import SIEM
            logger.info("Successfully imported SIEM module")
        except ImportError as e:
            logger.error(f"Failed to import SIEM module: {e}")
            logger.error("Please make sure the project is properly installed in development mode.")
            logger.error("Run: pip install -e .")
            return False
        
        # Initialize SIEM with test configuration
        try:
            logger.info("Initializing SIEM...")
            siem = SIEM()
            logger.info("SIEM initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SIEM: {e}", exc_info=True)
            return False
        
        # Test starting the SIEM
        try:
            logger.info("Starting SIEM...")
            siem.start()
            logger.info("SIEM started successfully")
            
            # Let it run for a few seconds
            logger.info("SIEM is running. Waiting for 5 seconds...")
            time.sleep(5)
            
            # Test stopping the SIEM
            logger.info("Stopping SIEM...")
            siem.stop()
            logger.info("SIEM stopped successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Error during SIEM operation: {e}", exc_info=True)
            return False
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("=== Starting SIEM Component Test ===")
    
    if test_siem_component():
        logger.info("=== SIEM Component Test PASSED ===")
        sys.exit(0)
    else:
        logger.error("=== SIEM Component Test FAILED ===")
        sys.exit(1)
