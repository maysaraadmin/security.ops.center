"""
Simplified SIEM launcher for debugging import issues.
"""

import os
import sys
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

logger = logging.getLogger('simple_siem')

def test_component_imports():
    """Test importing SIEM components one by one."""
    components = [
        'src.siem.core.log_collector',
        'src.siem.core.correlation_engine',
        'src.edr.server',
        'src.ndr.manager',
        'src.dlp.manager',
        'src.fim.manager',
        'src.hips.manager',
        'src.nips.manager',
        'src.siem.services.monitoring_service',
        'src.compliance.manager'
    ]
    
    for component in components:
        try:
            logger.info(f"Importing {component}...")
            __import__(component)
            logger.info(f"✅ Successfully imported {component}")
        except ImportError as e:
            logger.error(f"❌ Failed to import {component}: {e}")
        except Exception as e:
            logger.error(f"❌ Unexpected error importing {component}: {e}")

def main():
    """Main function to test SIEM component imports."""
    logger.info("Testing SIEM component imports...")
    test_component_imports()
    return 0

if __name__ == "__main__":
    sys.exit(main())
