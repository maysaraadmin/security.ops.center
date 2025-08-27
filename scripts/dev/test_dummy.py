"""
Test Dummy Component

A simple test script to verify the DummyComponent works as expected.
"""
import logging
import time
import sys
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('test_dummy.log')
    ]
)

logger = logging.getLogger('test_dummy')

def main():
    try:
        logger.info("=== Starting Dummy Component Test ===")
        
        # Import the component
        from src.siem.core.components.dummy_component import DummyComponent
        
        # Test configuration
        config = {
            'enabled': True,
            'interval': 3,  # Log every 3 seconds
            'test_setting': 'test_value'
        }
        
        logger.info("Creating DummyComponent instance...")
        dummy = DummyComponent(config)
        
        # Test get() method
        logger.info(f"Test get('test_setting'): {dummy.get('test_setting', 'not_found')}")
        logger.info(f"Test get('nonexistent', 'default'): {dummy.get('nonexistent', 'default_value')}")
        
        # Start the component
        logger.info("Starting DummyComponent...")
        if not dummy.start():
            logger.error("Failed to start DummyComponent")
            return 1
        
        # Let it run for a while
        logger.info("DummyComponent is running. Press Ctrl+C to stop...")
        try:
            for i in range(1, 4):
                logger.info(f"Main thread waiting... ({i}/3)")
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("\nReceived keyboard interrupt")
        
        # Stop the component
        logger.info("Stopping DummyComponent...")
        dummy.stop()
        
        logger.info("=== Test completed successfully ===")
        return 0
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
