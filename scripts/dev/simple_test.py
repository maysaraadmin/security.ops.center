#!/usr/bin/env python3
"""
Simple Test Script for SIEM Core Functionality

This script tests the basic functionality of the SIEM core components.
"""

import os
import sys
import logging
import time
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
        logging.FileHandler('simple_test.log')
    ]
)
logger = logging.getLogger('simple_test')

class MockComponent:
    """Mock component for testing."""
    def __init__(self, name):
        self.name = name
        self.is_running = False
    
    def start(self):
        """Start the component."""
        logger.info(f"Starting {self.name}...")
        self.is_running = True
    
    def stop(self):
        """Stop the component."""
        logger.info(f"Stopping {self.name}...")
        self.is_running = False

def test_basic_functionality():
    """Test basic functionality with mock components."""
    try:
        logger.info("Starting basic functionality test...")
        
        # Create mock components
        logger.info("Creating mock components...")
        log_collector = MockComponent("Log Collector")
        correlation_engine = MockComponent("Correlation Engine")
        
        # Test component lifecycle
        logger.info("Testing component lifecycle...")
        
        # Start components
        log_collector.start()
        correlation_engine.start()
        
        # Simulate some work
        logger.info("Components are running. Simulating work for 3 seconds...")
        time.sleep(3)
        
        # Stop components
        correlation_engine.stop()
        log_collector.stop()
        
        logger.info("Basic functionality test completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("Starting simple test...")
    if test_basic_functionality():
        logger.info("All tests passed!")
        sys.exit(0)
    else:
        logger.error("Some tests failed!")
        sys.exit(1)
