"""
FIM (File Integrity Monitoring) Demo

This script demonstrates the FIM system with ransomware detection capabilities.
It monitors a directory for changes and alerts on suspicious activity.
"""
import os
import sys
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from fim.core import FIMEngine, FileEvent, EventType
from fim.ransomware_detector import RansomwareDetector

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fim_demo.log')
    ]
)
logger = logging.getLogger(__name__)

class FIMDemo:
    """Demonstrates the FIM system with ransomware detection."""
    
    def __init__(self, monitor_path: str):
        """Initialize the FIM demo."""
        self.monitor_path = os.path.abspath(monitor_path)
        self.setup_directories()
        
        # Configure FIM engine
        self.config = {
            'baseline_file': 'fim_baseline.json',
            'enable_ransomware_detection': True,
            'ransomware_config': {
                'file_mod_threshold': 50,  # Alert if more than 50 files modified per minute
                'extension_change_threshold': 10,  # Alert if more than 10 extensions changed per minute
            },
            'exclude_patterns': [
                '*.tmp',
                '*.log',
                '*.swp',
                '~*',
                '*.bak',
                '*.tmp',
                '*.temp',
                '*.swp',
                '*.swx',
                '*.swo'
            ]
        }
        
        # Initialize FIM engine
        self.engine = FIMEngine(self.config)
        
        # Register event and alert handlers
        self.engine.add_handler(self.handle_file_event)
        self.engine.add_alert_callback(self.handle_alert)
        
        # Add the directory to monitor
        self.engine.add_monitor(self.monitor_path, recursive=True)
    
    def setup_directories(self) -> None:
        """Set up the directory structure for the demo."""
        # Create the monitor directory if it doesn't exist
        os.makedirs(self.monitor_path, exist_ok=True)
        logger.info(f"Monitoring directory: {self.monitor_path}")
    
    def handle_file_event(self, event: FileEvent) -> None:
        """Handle file system events."""
        event_type = event.event_type.name
        path = event.src_path
        
        # Skip directory events for cleaner output
        if event.is_directory:
            return
            
        timestamp = datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        if event_type == 'RENAMED':
            logger.info(f"[{timestamp}] {event_type}: {event.src_path} -> {event.dest_path}")
        else:
            logger.info(f"[{timestamp}] {event_type}: {path}")
    
    def handle_alert(self, alert: dict) -> None:
        """Handle security alerts."""
        timestamp = alert.get('timestamp', datetime.utcnow().isoformat())
        alert_type = alert.get('type', 'unknown_alert')
        message = alert.get('message', 'No details available')
        severity = alert.get('severity', 'medium').upper()
        
        # Format the alert message with emojis based on severity
        emoji = {
            'HIGH': '🔴',
            'MEDIUM': '🟠',
            'LOW': '🟡'
        }.get(severity, 'ℹ️')
        
        logger.warning(
            f"\n{emoji} [ALERT - {severity}] {alert_type.upper()}\n"
            f"   Timestamp: {timestamp}\n"
            f"   Message: {message}\n"
            f"   File: {alert.get('file_path', 'N/A')}\n"
            f"   Process: {alert.get('process', 'N/A')}\n"
            f"   Details: {alert.get('details', {})}\n"
            f"{'-' * 80}"
        )
    
    def run(self) -> None:
        """Run the FIM demo."""
        try:
            logger.info("Starting FIM demo...")
            logger.info("Press Ctrl+C to stop")
            
            # Create initial baseline
            logger.info("Creating initial baseline...")
            self.engine.create_baseline()
            
            # Start monitoring
            logger.info("Starting file system monitoring...")
            self.engine.start()
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("\nStopping FIM demo...")
            self.engine.stop()
            logger.info("FIM demo stopped")
        except Exception as e:
            logger.error(f"Error in FIM demo: {e}", exc_info=True)
            self.engine.stop()


def main():
    """Main entry point for the FIM demo."""
    parser = argparse.ArgumentParser(description='File Integrity Monitoring Demo')
    parser.add_argument(
        'path',
        nargs='?',
        default='monitor_me',
        help='Path to monitor (default: ./monitor_me)'
    )
    args = parser.parse_args()
    
    # Create and run the demo
    demo = FIMDemo(args.path)
    demo.run()


if __name__ == '__main__':
    main()
