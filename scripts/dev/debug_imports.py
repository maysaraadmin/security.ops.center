"""
Debug script to identify import issues in the SIEM module.
"""

import sys
import os
import importlib
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('debug_imports')

def debug_siem_import():
    """Debug the SIEM module import."""
    # Add the project root to the Python path
    project_root = str(Path(__file__).parent.absolute())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Test importing the SIEM module
    try:
        logger.info("1. Attempting to import SIEM module...")
        from src.siem.core import siem
        logger.info("✅ Successfully imported SIEM module")
        
        logger.info("2. Attempting to access SIEM class...")
        siem.SIEM
        logger.info("✅ Successfully accessed SIEM class")
        
        return True
    except ImportError as ie:
        logger.error(f"❌ ImportError: {ie}")
        logger.error("Full traceback:", exc_info=True)
        return False
    except AttributeError as ae:
        logger.error(f"❌ AttributeError: {ae}")
        logger.error("Full traceback:", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        logger.error("Full traceback:", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("Starting SIEM import debug...")
    if debug_siem_import():
        logger.info("✅ Debug completed successfully")
        sys.exit(0)
    else:
        logger.error("❌ Debug failed")
        sys.exit(1)
