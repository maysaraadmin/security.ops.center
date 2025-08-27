"""
Command-line interface for the Sysmon service.
"""
import argparse
import logging
import os
import signal
import sys
from typing import Optional

from src.siem.services.sysmon_service import SysmonService, run_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SysmonCLI:
    """Command-line interface for the Sysmon service."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.parser = self._create_parser()
        self.service = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser.
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description='SIEM Sysmon Event Collector',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Global arguments
        parser.add_argument(
            '--config',
            type=str,
            default=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 
                               'config', 'sysmon_config.yaml'),
            help='Path to the configuration file'
        )
        parser.add_argument(
            '--log-level',
            type=str,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            help='Logging level'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start the Sysmon service')
        start_parser.add_argument(
            '--foreground',
            action='store_true',
            help='Run in the foreground (do not daemonize)'
        )
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop the Sysmon service')
        
        # Restart command
        restart_parser = subparsers.add_parser('restart', help='Restart the Sysmon service')
        restart_parser.add_argument(
            '--foreground',
            action='store_true',
            help='Run in the foreground (do not daemonize)'
        )
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show the status of the Sysmon service')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Test the Sysmon service configuration')
        test_parser.add_argument(
            '--collect',
            type=int,
            default=5,
            help='Number of events to collect for testing'
        )
        
        # Install command
        install_parser = subparsers.add_parser('install', help='Install the Sysmon service')
        
        # Uninstall command
        uninstall_parser = subparsers.add_parser('uninstall', help='Uninstall the Sysmon service')
        
        # Version command
        version_parser = subparsers.add_parser('version', help='Show version information')
        
        return parser
    
    def parse_args(self, args: Optional[list] = None) -> argparse.Namespace:
        """Parse command-line arguments.
        
        Args:
            args: Command-line arguments (default: sys.argv[1:])
            
        Returns:
            Parsed arguments
        """
        return self.parser.parse_args(args)
    
    def run(self, args: Optional[list] = None) -> int:
        """Run the CLI.
        
        Args:
            args: Command-line arguments (default: sys.argv[1:])
            
        Returns:
            Exit code
        """
        # Parse arguments
        parsed_args = self.parse_args(args)
        
        # Set log level
        logging.getLogger().setLevel(parsed_args.log_level)
        
        # Handle commands
        if not parsed_args.command:
            self.parser.print_help()
            return 0
        
        try:
            # Get the method to handle the command
            handler = getattr(self, f'handle_{parsed_args.command}')
            return handler(parsed_args)
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            if parsed_args.log_level == 'DEBUG':
                logger.exception("Detailed error:")
            return 1
    
    def handle_start(self, args: argparse.Namespace) -> int:
        """Handle the start command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        logger.info("Starting Sysmon service...")
        
        if args.foreground:
            # Run in the foreground
            try:
                run_service(args.config)
                return 0
            except KeyboardInterrupt:
                logger.info("Stopping Sysmon service...")
                return 0
            except Exception as e:
                logger.error(f"Failed to start Sysmon service: {str(e)}")
                return 1
        else:
            # Run as a daemon
            try:
                # In a real implementation, you would use a proper daemonization library
                # like python-daemon or create a Windows service
                logger.warning("Daemon mode not yet implemented. Running in foreground.")
                run_service(args.config)
                return 0
            except KeyboardInterrupt:
                logger.info("Stopping Sysmon service...")
                return 0
            except Exception as e:
                logger.error(f"Failed to start Sysmon service: {str(e)}")
                return 1
    
    def handle_stop(self, args: argparse.Namespace) -> int:
        """Handle the stop command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        logger.info("Stopping Sysmon service...")
        
        # In a real implementation, you would signal the running service to stop
        # For now, we'll just print a message
        logger.warning("Stop command not yet fully implemented")
        
        return 0
    
    def handle_restart(self, args: argparse.Namespace) -> int:
        """Handle the restart command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        logger.info("Restarting Sysmon service...")
        
        # Stop the service
        self.handle_stop(args)
        
        # Start the service
        return self.handle_start(args)
    
    def handle_status(self, args: argparse.Namespace) -> int:
        """Handle the status command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        # In a real implementation, you would check if the service is running
        # For now, we'll just print a message
        logger.info("Status: Not implemented yet")
        return 0
    
    def handle_test(self, args: argparse.Namespace) -> int:
        """Handle the test command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        from src.siem.collectors.sysmon_collector import collect_sysmon_events
        
        logger.info(f"Collecting {args.collect} Sysmon events...")
        
        try:
            events = collect_sysmon_events()
            
            if not events:
                logger.warning("No events found")
                return 0
            
            # Print the events
            import json
            print(json.dumps(events[:args.collect], indent=2))
            
            logger.info(f"Collected {len(events)} events (showing first {min(args.collect, len(events))})")
            return 0
            
        except Exception as e:
            logger.error(f"Error collecting events: {str(e)}")
            return 1
    
    def handle_install(self, args: argparse.Namespace) -> int:
        """Handle the install command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        logger.info("Installing Sysmon service...")
        
        # In a real implementation, you would create a Windows service
        # or a systemd service file
        logger.warning("Install command not yet implemented")
        
        return 0
    
    def handle_uninstall(self, args: argparse.Namespace) -> int:
        """Handle the uninstall command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        logger.info("Uninstalling Sysmon service...")
        
        # In a real implementation, you would remove the Windows service
        # or systemd service file
        logger.warning("Uninstall command not yet implemented")
        
        return 0
    
    def handle_version(self, args: argparse.Namespace) -> int:
        """Handle the version command.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        print("SIEM Sysmon Collector v1.0.0")
        return 0


def main() -> int:
    """Main entry point for the CLI.
    
    Returns:
        Exit code
    """
    # Handle keyboard interrupt
    def signal_handler(signum, frame):
        print("\nOperation cancelled by user")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Run the CLI
    cli = SysmonCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
