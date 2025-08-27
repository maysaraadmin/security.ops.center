"""
Test script to check SIEM module import structure.
"""

import sys
import os
import importlib
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

logger = logging.getLogger('import_test')

def check_import(module_path):
    """Check if a module can be imported."""
    try:
        logger.info(f"Trying to import: {module_path}")
        module = importlib.import_module(module_path)
        logger.info(f"✅ Successfully imported: {module_path}")
        return True
    except ImportError as e:
        logger.error(f"❌ Failed to import {module_path}: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error importing {module_path}: {e}")
        return False

def main():
    """Test the import of SIEM modules."""
    modules_to_test = [
        'src.siem',
        'src.siem.core',
        'src.siem.core.siem',
        'src.siem.launcher'
    ]
    
    results = {}
    for module in modules_to_test:
        results[module] = check_import(module)
    
    # Print summary
    logger.info("\n=== Import Test Results ===")
    for module, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        logger.info(f"{status} - {module}")
    
    return 0 if all(results.values()) else 1

if __name__ == "__main__":
    sys.exit(main())
