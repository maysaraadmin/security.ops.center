"""
Diagnose and fix SIEM component initialization issues.
"""

import sys
import os
import importlib
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fix_siem.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('fix_siem')

def check_siem_module():
    """Check if the SIEM module can be imported and initialized."""
    try:
        # Try to import the SIEM module
        logger.info("Attempting to import SIEM module...")
        siem_module = importlib.import_module('src.siem.core.siem')
        logger.info("✅ Successfully imported SIEM module")
        
        # Check if SIEM class exists
        if hasattr(siem_module, 'SIEM'):
            logger.info("✅ Found SIEM class")
            return True, siem_module.SIEM
        else:
            logger.error("❌ SIEM class not found in module")
            return False, None
            
    except Exception as e:
        logger.error(f"❌ Failed to import SIEM module: {e}", exc_info=True)
        return False, None

def check_launcher():
    """Check the SIEM launcher functionality."""
    try:
        logger.info("\nChecking SIEM launcher...")
        from src.siem.launcher import SIEMLauncher
        
        # Create a minimal config
        config = {
            'siem': {
                'enabled': True,
                'log_level': 'DEBUG',
                'log_file': 'logs/siem_test.log'
            }
        }
        
        # Try to initialize the launcher
        logger.info("Initializing SIEM launcher...")
        launcher = SIEMLauncher(config)
        
        if launcher.initialize():
            logger.info("✅ SIEM launcher initialized successfully")
            
            # Try to start the launcher
            logger.info("Starting SIEM launcher...")
            launcher.start()
            
            # Let it run for a few seconds
            import time
            time.sleep(2)
            
            # Check status
            status = launcher.get_status()
            logger.info(f"SIEM status: {status}")
            
            # Stop the launcher
            logger.info("Stopping SIEM launcher...")
            launcher.stop()
            
            return True
        else:
            logger.error("❌ Failed to initialize SIEM launcher")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error testing SIEM launcher: {e}", exc_info=True)
        return False

def main():
    """Main function to diagnose and fix SIEM component."""
    logger.info("="*50)
    logger.info("SIEM Component Diagnostic Tool")
    logger.info("="*50)
    
    # Check if running in the correct directory
    if not os.path.exists('src') or not os.path.exists('config'):
        logger.error("❌ Please run this script from the project root directory")
        return 1
    
    # Add project root to Python path
    project_root = str(Path(__file__).parent.absolute())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Check SIEM module
    logger.info("\n[1/2] Checking SIEM module...")
    siem_ok, siem_class = check_siem_module()
    
    # Check launcher
    logger.info("\n[2/2] Checking SIEM launcher...")
    launcher_ok = check_launcher()
    
    # Print summary
    logger.info("\n" + "="*50)
    logger.info("DIAGNOSTIC SUMMARY")
    logger.info("="*50)
    logger.info(f"SIEM Module: {'✅' if siem_ok else '❌'}")
    logger.info(f"SIEM Launcher: {'✅' if launcher_ok else '❌'}")
    
    if siem_ok and launcher_ok:
        logger.info("\n✅ SIEM component appears to be working correctly")
        return 0
    else:
        logger.error("\n❌ Issues were found with the SIEM component")
        logger.info("\nRECOMMENDED ACTIONS:")
        if not siem_ok:
            logger.info("1. Check the SIEM module implementation at 'src/siem/core/siem.py'")
            logger.info("2. Verify that all required dependencies are installed")
        if not launcher_ok:
            logger.info("3. Review the SIEM launcher at 'src/siem/launcher.py'")
            logger.info("4. Check the configuration in 'config/siem_config.yaml'")
        return 1

if __name__ == "__main__":
    sys.exit(main())
