#!/usr/bin/env python3
"""
EDR Agent Command Line Interface

This script provides a command-line interface to manage the EDR agent.
"""
import argparse
import signal
import sys
import logging
from models.edr_agent import create_edr_agent

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='EDR Agent Management')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start the EDR agent')
    start_parser.add_argument('--siem-endpoint', required=True, 
                            help='SIEM endpoint to send alerts to')
    start_parser.add_argument('--interval', type=int, default=60,
                            help='Check interval in seconds (default: 60)')
    start_parser.add_argument('--log-level', default='INFO',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help='Logging level (default: INFO)')
    
    # Status command
    subparsers.add_parser('status', help='Check EDR agent status')
    
    # Stop command
    subparsers.add_parser('stop', help='Stop the EDR agent')
    
    return parser.parse_args()

def setup_logging(level='INFO'):
    """Configure logging"""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def main():
    """Main entry point for the EDR CLI"""
    args = parse_arguments()
    setup_logging(args.log_level if hasattr(args, 'log_level') else 'INFO')
    logger = logging.getLogger('edr_cli')
    
    # Handle commands
    if args.command == 'start':
        logger.info(f"Starting EDR Agent with SIEM endpoint: {args.siem_endpoint}")
        
        # Create and start the agent
        agent = create_edr_agent(
            siem_endpoint=args.siem_endpoint,
            check_interval=args.interval
        )
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutting down EDR Agent...")
            agent.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep the main thread alive
        try:
            while True:
                signal.pause()
        except (KeyboardInterrupt, SystemExit):
            agent.stop()
            
    elif args.command == 'status':
        # TODO: Implement status check
        print("EDR Agent status check not yet implemented")
        
    elif args.command == 'stop':
        # TODO: Implement stop functionality
        print("EDR Agent stop not yet implemented")
        
    else:
        print("No command specified. Use --help for usage information.")
        sys.exit(1)

if __name__ == "__main__":
    main()
