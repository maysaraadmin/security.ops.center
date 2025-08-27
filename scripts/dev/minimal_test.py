#!/usr/bin/env python3
"""
Minimal Test for SIEM Component

This script tests the basic functionality of the SIEM component with proper error handling.
"""

import os
import sys
import logging
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
        logging.FileHandler('minimal_test.log')
    ]
)
logger = logging.getLogger('minimal_test')

def test_minimal():
    """Test minimal SIEM functionality."""
    try:
        logger.info("Starting minimal test...")
        
        # Try to import the SIEM module
        try:
            logger.info("Attempting to import SIEM module...")
            from src.siem.core.siem import SIEM
            logger.info("Successfully imported SIEM module")
            return True
            
        except ImportError as e:
            logger.error(f"Failed to import SIEM module: {e}")
            logger.error("Python path: %s", sys.path)
            return False
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("=== Starting Minimal Test ===")
    
    if test_minimal():
        logger.info("=== Minimal Test PASSED ===")
        sys.exit(0)
    else:
        logger.error("=== Minimal Test FAILED ===")
        sys.exit(1)
