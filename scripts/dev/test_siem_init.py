"""
Test script for SIEM component initialization.
"""

import os
import sys
import logging
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
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('test_siem')

def test_siem_initialization():
    """Test SIEM component initialization."""
    try:
        logger.info("Testing SIEM initialization...")
        
        # Import SIEM launcher
        from src.siem.launcher import SIEMLauncher
        
        # Use the existing config file
        config_path = os.path.join('config', 'siem_config.yaml')
        logger.info(f"Using config file: {os.path.abspath(config_path)}")
        
        # Load the config file directly to verify it
        import yaml
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            logger.info("Successfully loaded config file")
        
        # Create a minimal configuration for the launcher
        launcher_config = {
            'siem': config  # Pass the entire config as the SIEM config
        }
        
        # Initialize the launcher with the config
        logger.info("Creating SIEMLauncher...")
        launcher = SIEMLauncher(launcher_config)
        
        # Test initialization
        logger.info("Initializing SIEM component...")
        if launcher.initialize():
            logger.info("✅ SIEM initialized successfully")
            
            # Test starting
            logger.info("Starting SIEM component...")
            launcher.start()
            
            # Test status
            status = launcher.get_status()
            logger.info(f"SIEM status: {status}")
            
            # Let it run for a bit
            import time
            logger.info("SIEM running for 5 seconds...")
            time.sleep(5)
            
            # Test stopping
            logger.info("Stopping SIEM component...")
            launcher.stop()
            logger.info("✅ Test completed successfully")
            return True
        else:
            logger.error("❌ Failed to initialize SIEM")
            return False
            
    except Exception as e:
        logger.error(f"❌ Test failed with error: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    if test_siem_initialization():
        sys.exit(0)
    else:
        sys.exit(1)
