#!/usr/bin/env python3
"""
Test Script for SIEM Component

This script tests the basic functionality of the SIEM component.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
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

def test_siem_initialization():
    """Test the SIEM component initialization."""
    try:
        from src.siem.core.siem import SIEM
        
        logger.info("Testing SIEM initialization...")
        siem = SIEM()
        logger.info("SIEM initialized successfully!")
        
        # Test basic functionality
        logger.info("Testing SIEM start...")
        siem.start()
        logger.info("SIEM started successfully!")
        
        # Let it run for a few seconds
        import time
        logger.info("SIEM is running. Press Ctrl+C to stop...")
        time.sleep(5)
        
        logger.info("Testing SIEM stop...")
        siem.stop()
        logger.info("SIEM stopped successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"SIEM test failed: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("Starting SIEM test...")
    if test_siem_initialization():
        logger.info("SIEM test completed successfully!")
        sys.exit(0)
    else:
        logger.error("SIEM test failed!")
        sys.exit(1)
