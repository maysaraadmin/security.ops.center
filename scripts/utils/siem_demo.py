#!/usr/bin/env python3
"""
SIEM System Demo

This script demonstrates the core functionality of the SIEM system,
including log collection, event correlation, alerting, and more.
"""

import os
import sys
import time
import json
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.siem import SIEM
from core.alert_manager import AlertManager, AlertSeverity, AlertStatus
from core.log_collector import LogCollector
from core.correlation_engine import CorrelationEngine, CorrelationRule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_demo.log')
    ]
)
logger = logging.getLogger('siem.demo')

class SIEMDemo:
    """Demonstration of SIEM system functionality."""
    
    def __init__(self):
        """Initialize the SIEM demo."""
        self.temp_dir = tempfile.mkdtemp(prefix='siem_demo_')
        self.setup_demo_environment()
        
        # Initialize SIEM with demo configuration
        self.siem = self.create_siem_config()
        
        # Keep track of demo components
        self.running = False
    
    def setup_demo_environment(self):
        """Set up the demo environment with test files and logs."""
        logger.info(f"Setting up demo environment in {self.temp_dir}")
        
        # Create test log files
        self.syslog_file = os.path.join(self.temp_dir, 'syslog.log')
        self.windows_log_file = os.path.join(self.temp_dir, 'windows_events.log')
        self.custom_log_file = os.path.join(self.temp_dir, 'custom_app.log')
        
        # Initialize log files with sample data
        with open(self.syslog_file, 'w') as f:
            f.write(
                '<34>Oct 11 22:14:15 server1 su: ' + 
                "'su root' failed for user1 on /dev/pts/8\n"
            )
            f.write(
                '<30>Oct 11 22:15:00 server1 sshd[1234]: ' + 
                'Accepted password for user2 from 192.168.1.100 port 54321 ssh2\n'
            )
        
        with open(self.windows_log_file, 'w') as f:
            f.write(json.dumps({
                'TimeGenerated': '2023-10-11T22:15:30Z',
                'SourceName': 'Microsoft-Windows-Security-Auditing',
                'EventID': 4625,
                'Level': 2,
                'Message': 'An account failed to log on.',
                'User': 'ATTACKER\\baduser',
                'IpAddress': '10.0.0.100',
                'LogonType': 3
            }) + '\n')
        
        with open(self.custom_log_file, 'w') as f:
            f.write('2023-10-11 22:16:00 - WARNING - API rate limit exceeded\n')
            f.write('2023-10-11 22:16:05 - ERROR - Database connection failed\n')
    
    def create_siem_config(self):
        """Create a SIEM instance with demo configuration."""
        config = {
            'global': {
                'log_level': 'INFO'
            },
            'log_collection': {
                'enabled': True,
                'sources': [
                    {
                        'type': 'file',
                        'path': self.syslog_file,
                        'format': 'syslog',
                        'enabled': True
                    },
                    {
                        'type': 'file',
                        'path': self.windows_log_file,
                        'format': 'json',
                        'enabled': True
                    },
                    {
                        'type': 'file',
                        'path': self.custom_log_file,
                        'format': 'custom',
                        'pattern': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (?P<level>\w+) - (?P<message>.*)',
                        'enabled': True
                    }
                ]
            },
            'correlation': {
                'enabled': True,
                'rules': [
                    {
                        'id': 'failed_login_attempts',
                        'name': 'Multiple Failed Login Attempts',
                        'description': 'Detect multiple failed login attempts from the same source',
                        'condition': "event.get('event_type') == 'authentication_failure'",
                        'group_by': ['source_ip', 'user'],
                        'time_window': 300,
                        'threshold': 3,
                        'severity': 'HIGH',
                        'actions': ['alert'],
                        'enabled': True
                    },
                    {
                        'id': 'high_severity_error',
                        'name': 'High Severity Error',
                        'description': 'Detect high severity error messages',
                        'condition': (
                            "event.get('severity') == 'error' or "
                            "event.get('level') == 'error' or "
                            "event.get('EventID') in [4625]"
                        ),
                        'severity': 'HIGH',
                        'actions': ['alert'],
                        'enabled': True
                    }
                ]
            },
            'alerting': {
                'enabled': True,
                'providers': [
                    {
                        'type': 'console',
                        'enabled': True,
                        'min_severity': 'LOW'
                    },
                    {
                        'type': 'file',
                        'enabled': True,
                        'path': os.path.join(self.temp_dir, 'alerts.log'),
                        'min_severity': 'LOW'
                    }
                ]
            },
            'modules': {
                'edr': {'enabled': False},
                'ndr': {'enabled': False},
                'dlp': {'enabled': False},
                'fim': {'enabled': False},
                'hips': {'enabled': False},
                'nips': {'enabled': False},
                'compliance': {'enabled': False}
            }
        }
        
        return SIEM(config)
    
    def generate_test_events(self):
        """Generate test events to demonstrate SIEM functionality."""
        logger.info("Generating test events...")
        
        # Add more failed login attempts to trigger correlation
        with open(self.syslog_file, 'a') as f:
            for i in range(1, 4):
                log_entry = (
                    f'<34>Oct 11 22:16:{15 + i:02d} server1 su: ' + \
                    f"'su root' failed for user1 on /dev/pts/8\n"
                )
                f.write(log_entry)
                time.sleep(0.5)
        
        # Add a high severity error
        with open(self.custom_log_file, 'a') as f:
            f.write('2023-10-11 22:17:00 - ERROR - Critical system failure\n')
    
    def run_demo(self, duration=30):
        """Run the SIEM demo for the specified duration."""
        logger.info("Starting SIEM demo...")
        self.running = True
        
        try:
            # Start the SIEM system
            self.siem.start()
            logger.info("SIEM system started")
            
            # Generate test events after a short delay
            time.sleep(2)
            self.generate_test_events()
            
            # Let the system process events
            logger.info(f"Running demo for {duration} seconds...")
            time.sleep(duration)
            
        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")
        except Exception as e:
            logger.error(f"Error in demo: {e}", exc_info=True)
        finally:
            # Stop the SIEM system
            self.siem.stop()
            self.running = False
            logger.info("SIEM demo completed")
            
            # Print demo summary
            self.print_demo_summary()
    
    def print_demo_summary(self):
        """Print a summary of the demo results."""
        print("\n" + "=" * 50)
        print("SIEM DEMO SUMMARY")
        print("=" * 50)
        
        # Print generated log files
        print("\nGenerated Log Files:")
        for log_file in [self.syslog_file, self.windows_log_file, self.custom_log_file]:
            print(f"- {log_file}")
        
        # Print alerts if any
        alert_log = os.path.join(self.temp_dir, 'alerts.log')
        if os.path.exists(alert_log):
            print("\nGenerated Alerts:")
            with open(alert_log, 'r') as f:
                print(f.read())
        
        print("\nDemo files and logs are available in:", self.temp_dir)
        print("=" * 50 + "\n")

def main():
    """Main entry point for the SIEM demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM System Demo')
    parser.add_argument('--duration', type=int, default=30,
                       help='Duration of the demo in seconds (default: 30)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run the demo
    demo = SIEMDemo()
    demo.run_demo(duration=args.duration)

if __name__ == "__main__":
    main()
