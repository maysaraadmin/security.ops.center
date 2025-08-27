"""
Simple test script to verify launcher functionality with detailed logging.
"""

import sys
import os
import time
import logging
from pathlib import Path

# Fix for Unicode characters in Windows console
if sys.platform == 'win32':
    import io
    import sys
    # Set console output code page to UTF-8
    os.system('chcp 65001')
    # Reopen stdout and stderr with UTF-8 encoding
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# Set up basic logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_launcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def test_component(component_name):
    """Test a single component launcher."""
    logger.info(f"Testing {component_name} launcher...")
    
    try:
        # Import the launcher module
        module_name = f"src.{component_name}.launcher"
        logger.info(f"Importing {module_name}...")
        module = __import__(module_name, fromlist=['*'])
        logger.info(f"Successfully imported {module_name}")
        
        # Get the launcher class
        launcher_class = getattr(module, f"{component_name.upper()}Launcher")
        logger.info(f"Found launcher class: {launcher_class.__name__}")
        
        # Create a simple config
        config = {
            component_name: {
                "enabled": True,
                "log_level": "DEBUG",
                "log_file": f"logs/{component_name}.log"
            }
        }
        
        # Initialize the launcher
        logger.info(f"Initializing {component_name}...")
        launcher = launcher_class(config)
        
        # Test initialization
        if launcher.initialize():
            logger.info(f"{component_name} initialized successfully")
            
            # Test starting
            logger.info(f"Starting {component_name}...")
            launcher.start()
            logger.info(f"{component_name} started")
            
            # Let it run for a few seconds
            logger.info(f"{component_name} is running for 5 seconds...")
            time.sleep(5)
            
            # Test status
            status = launcher.get_status()
            logger.info(f"{component_name} status: {status}")
            
            # Test stopping
            logger.info(f"Stopping {component_name}...")
            launcher.stop()
            logger.info(f"{component_name} stopped")
            
            return True
        else:
            logger.error(f"Failed to initialize {component_name}")
            return False
            
    except Exception as e:
        logger.error(f"Error testing {component_name}: {e}", exc_info=True)
        return False

def main():
    """Main test function."""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Test each component
    components = ["siem", "edr", "dlp", "hips", "nips"]
    results = {}
    
    for component in components:
        logger.info(f"\n{'\u2500'*50}")
        logger.info(f"\u2705 TESTING {component.upper()}")
        logger.info(f"{'\u2500'*50}")
        success = test_component(component)
        results[component] = success
        status = "\u2713[PASS]" if success else "\u2717[FAIL]"
        logger.info(f"{component.upper()}: {status}")
    
    # Print summary with Unicode characters for better Windows compatibility
    logger.info("\n" + "\u2500"*50)
    logger.info("\u2705 TEST SUMMARY")
    logger.info("\u2500"*50)
    for component, success in results.items():
        status = "\u2713[PASS]" if success else "\u2717[FAIL]"
        status = "[PASS]" if success else "[FAIL]"
        logger.info(f"{component.upper()}: {status}")
    
    # Return appropriate exit code
    if all(results.values()):
        logger.info("\n[SUCCESS] All tests passed!")
        sys.exit(0)
    else:
        logger.error("\n[ERROR] Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
