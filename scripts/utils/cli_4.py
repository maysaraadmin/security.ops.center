#!/usr/bin/env python3
"""
SOC Command Line Interface

This module provides a command-line interface for managing the Security Operations Center.
"""

import argparse
import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('soc_cli.log')
    ]
)
logger = logging.getLogger('soc.cli')

def start_soc():
    """Start the SOC services."""
    try:
        from .siem import SIEM
        
        logger.info("Starting Security Operations Center...")
        
        # Initialize SIEM
        siem = SIEM()
        siem.start()
        
        # Keep the application running
        try:
            while True:
                command = input("Enter 'stop' to shut down: ").strip().lower()
                if command == 'stop':
                    break
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt. Shutting down...")
        finally:
            # Stop SIEM
            siem.stop()
            logger.info("Security Operations Center has been shut down.")
            
    except Exception as e:
        logger.error(f"Failed to start SOC: {e}", exc_info=True)
        return 1
    
    return 0

def check_status():
    """Check the status of SOC services."""
    logger.info("Checking SOC services status...")
    # TODO: Implement actual status checking
    logger.info("Status check not yet implemented.")
    return 0

def main():
    """Main entry point for the SOC CLI."""
    parser = argparse.ArgumentParser(description='Security Operations Center CLI')
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start SOC services')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check SOC services status')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute the appropriate command
    if args.command == 'start':
        return start_soc()
    elif args.command == 'status':
        return check_status()
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
