"""
Test script to check imports step by step.
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

logger = logging.getLogger('test_imports')

def test_import(module_name, class_name=None):
    """Test importing a module and optionally a class from it."""
    try:
        logger.info(f"Importing module: {module_name}")
        module = importlib.import_module(module_name)
        logger.info(f"✅ Successfully imported {module_name}")
        
        if class_name:
            logger.info(f"Accessing class: {class_name}")
            getattr(module, class_name)
            logger.info(f"✅ Successfully accessed {class_name} from {module_name}")
            
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

def main():
    """Test imports step by step."""
    # Add the project root to the Python path
    project_root = str(Path(__file__).parent.absolute())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Test imports step by step
    steps = [
        ("src.siem.core.siem", "SIEM"),
        ("src.siem.core.log_collector", "LogCollector"),
        ("src.siem.core.correlation_engine", "CorrelationEngine"),
        ("src.siem.launcher", "SIEMLauncher"),
    ]
    
    all_success = True
    for module_name, class_name in steps:
        if not test_import(module_name, class_name):
            all_success = False
            break
    
    return 0 if all_success else 1

if __name__ == "__main__":
    sys.exit(main())
