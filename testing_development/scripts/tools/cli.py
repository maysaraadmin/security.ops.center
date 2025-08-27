"""
SIEM System CLI

This module provides a command-line interface for managing SIEM services.
"""
import argparse
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.service_manager import ServiceManager
from services.siem import SIEMManager
from services.edr import EDRManager
from services.ndr import NDRManager
from services.dlp import DLPService
from services.fim import FIMService
from services.nips import nips_manager as NIPSService
from services.hips import hips_manager as HIPSService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('siem.cli')

class SIEMCLI:
    """Command-line interface for managing SIEM services."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.service_manager = ServiceManager()
        self._register_services()
        self.parser = self._create_parser()
    
    def _register_services(self):
        """Register all available services."""
        # Register all services
        self.service_manager.register_service('siem', SIEMManager())
        self.service_manager.register_service('edr', EDRManager())
        self.service_manager.register_service('ndr', NDRManager())
        self.service_manager.register_service('dlp', DLPService())
        self.service_manager.register_service('fim', FIMService())
        self.service_manager.register_service('nips', NIPSService)
        self.service_manager.register_service('hips', HIPSService)
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(description='SIEM System Management CLI')
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start services')
        start_parser.add_argument('services', nargs='*', help='Services to start (default: all)')
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop services')
        stop_parser.add_argument('services', nargs='*', help='Services to stop (default: all)')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show service status')
        status_parser.add_argument('services', nargs='*', help='Services to check (default: all)')
        
        # List command
        subparsers.add_parser('list', help='List all available services')
        
        return parser
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI.
        
        Args:
            args: Command-line arguments (default: sys.argv[1:])
            
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        if args is None:
            args = sys.argv[1:]
            
        if not args:
            args = ['--help']
        
        try:
            parsed_args = self.parser.parse_args(args)
            
            if parsed_args.command == 'start':
                return self._handle_start(parsed_args.services)
            elif parsed_args.command == 'stop':
                return self._handle_stop(parsed_args.services)
            elif parsed_args.command == 'status':
                return self._handle_status(parsed_args.services)
            elif parsed_args.command == 'list':
                return self._handle_list()
            else:
                self.parser.print_help()
                return 0
                
        except Exception as e:
            logger.error(f"Error: {e}")
            if '--debug' in args:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_start(self, services: List[str]) -> int:
        """Handle the start command."""
        if not services:
            # Start all services
            results = self.service_manager.start_all()
        else:
            results = {}
            for service in services:
                results[service] = self.service_manager.start_service(service)
        
        self._print_results("Start", results)
        return 0 if all(results.values()) else 1
    
    def _handle_stop(self, services: List[str]) -> int:
        """Handle the stop command."""
        if not services:
            # Stop all services
            results = self.service_manager.stop_all()
        else:
            results = {}
            for service in services:
                results[service] = self.service_manager.stop_service(service)
        
        self._print_results("Stop", results)
        return 0 if all(results.values()) else 1
    
    def _handle_status(self, services: List[str]) -> int:
        """Handle the status command."""
        if not services:
            # Show status of all services
            statuses = self.service_manager.get_all_status()
        else:
            statuses = {}
            for service in services:
                status = self.service_manager.get_service_status(service)
                if status is not None:
                    statuses[service] = status
        
        self._print_status(statuses)
        return 0
    
    def _handle_list(self) -> int:
        """Handle the list command."""
        statuses = self.service_manager.get_all_status()
        print("\nAvailable services:")
        for service, status in statuses.items():
            state = 'running' if status.get('running', False) else 'stopped'
            print(f"  {service:10} - {state}")
        print()
        return 0
    
    def _print_results(self, action: str, results: Dict[str, bool]) -> None:
        """Print the results of an action."""
        print(f"\n{action} results:")
        for service, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            print(f"  {service:10} - {status}")
        print()
    
    def _print_status(self, statuses: Dict[str, Dict[str, Any]]) -> None:
        """Print the status of services."""
        print("\nService status:")
        for service, status in statuses.items():
            state = 'RUNNING' if status.get('running', False) else 'STOPPED'
            print(f"\n{service.upper()} - {state}")
            
            # Print component status if available
            if 'components' in status:
                print("  Components:")
                for comp, comp_status in status['components'].items():
                    print(f"    {comp}: {comp_status}")
            
            # Print stats if available
            if 'stats' in status:
                print("  Statistics:")
                for stat, value in status['stats'].items():
                    print(f"    {stat.replace('_', ' ').title()}: {value}")
        print()

def main():
    """Main entry point for the CLI."""
    cli = SIEMCLI()
    sys.exit(cli.run())

if __name__ == "__main__":
    main()
