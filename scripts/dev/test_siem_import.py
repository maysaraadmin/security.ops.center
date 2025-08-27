"""
Test script to verify SIEM module import.
"""

import sys
import os
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('test_import')

def test_siem_import():
    """Test importing the SIEM module."""
    try:
        logger.info("Attempting to import SIEM module...")
        from src.siem.core.siem import SIEM
        logger.info("✅ Successfully imported SIEM class")
        return True
    except ImportError as ie:
        logger.error(f"❌ Failed to import SIEM module: {ie}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error importing SIEM module: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    if test_siem_import():
        sys.exit(0)
    else:
        sys.exit(1)
