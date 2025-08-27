"""
SIEM Command Line Interface
This script provides a command-line interface for the SIEM system.
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_cli.log')
    ]
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
sys.path.insert(0, project_root)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SIEM Command Line Interface')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--log-level', '-l', default='INFO',
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      help='Set the logging level')
    return parser.parse_args()

def main():
    """Main entry point for the SIEM CLI."""
    args = parse_arguments()
    
    # Set log level
    logger.setLevel(args.log_level)
    
    logger.info("SIEM system started in CLI mode")
    logger.info("Web GUI has been removed from this installation")
    print("\nSIEM Command Line Interface")
    print("---------------------------")
    print("The web GUI has been removed from this installation.")
    print("Please use the command line interface instead.\n")
    
    # Here you would add your CLI functionality
    print("Available commands:")
    print("  - analyze: Run security analysis")
    print("  - monitor: Start monitoring")
    print("  - report: Generate reports\n")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
