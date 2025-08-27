"""
Example usage of the Network Detection and Response (NDR) system.
"""
import argparse
import logging
import time
from pathlib import Path
import sys

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.ndr.manager import NDRManager

def setup_logging(verbose: bool = False):
    """Configure logging for the example."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def main():
    """Run the NDR example."""
    parser = argparse.ArgumentParser(description="Network Detection and Response Example")
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter expression")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Network Detection and Response (NDR) example")
    logger.info(f"Interface: {args.interface or 'default'}")
    logger.info(f"Filter: {args.filter}")
    
    try:
        # Create and start the NDR manager
        ndr = NDRManager(interface=args.interface, filter_exp=args.filter)
        ndr.start()
        
        # Run for a while, printing status updates
        logger.info("NDR system started. Press Ctrl+C to stop.")
        
        try:
            while True:
                status = ndr.get_status()
                logger.info(
                    f"Status: {status['packets_processed']} packets processed, "
                    f"{status['alerts_triggered']} alerts triggered"
                )
                time.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
            
        finally:
            # Stop the NDR system
            ndr.stop()
            
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        return 1
    
    logger.info("NDR example completed")
    return 0

if __name__ == "__main__":
    sys.exit(main())
