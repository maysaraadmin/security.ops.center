"""
Simple launcher for the SimpleSIEM.
"""

import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('simple_launcher')

def main():
    """Run the SimpleSIEM launcher."""
    try:
        # Add the project root to the Python path
        project_root = str(Path(__file__).parent.absolute())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        logger.info("Importing SimpleSIEM...")
        from src.siem.core.simple_siem import SimpleSIEM
        
        logger.info("Creating SimpleSIEM instance...")
        siem = SimpleSIEM()
        
        logger.info("Starting SimpleSIEM...")
        siem.start()
        
        return 0
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
