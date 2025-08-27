"""
Endpoint DLP Demo

This script demonstrates how to use the Endpoint DLP monitoring capabilities.
"""
import os
import sys
import time
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from siem.dlp import PolicyEnforcer, PolicyScope, EndpointMonitor
from siem.dlp.endpoint_monitor import EndpointActivityType, EndpointActivity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('endpoint_dlp_demo.log')
    ]
)
logger = logging.getLogger(__name__)

def activity_callback(activity):
    """Callback function to handle endpoint activities."""
    logger.info(f"Activity detected: {activity.activity_type.name}")
    logger.info(f"  Process: {activity.process_name} (PID: {activity.process_id})")
    logger.info(f"  User: {activity.user}")
    logger.info(f"  Timestamp: {activity.timestamp}")
    
    # Log details specific to the activity type
    if activity.activity_type == EndpointActivityType.USB_DEVICE_CONNECTED:
        logger.info(f"  Device connected: {activity.details.get('device_path')}")
        logger.info(f"  Volume name: {activity.details.get('volume_name')}")
        logger.info(f"  Serial number: {activity.details.get('serial_number')}")
    
    elif activity.activity_type == EndpointActivityType.CLIPBOARD_COPY:
        logger.info(f"  Data type: {activity.details.get('data_type')}")
        data_preview = activity.details.get('data_preview', '') or ""
        logger.info(f"  Data preview: {data_preview[:100]}...")
    
    elif activity.activity_type == EndpointActivityType.SCREEN_CAPTURE:
        logger.info(f"  Window title: {activity.details.get('window_title')}")
    
    logger.info("-" * 80)

def main():
    """Run the endpoint DLP demo."""
    logger.info("Starting Endpoint DLP Demo")
    
    # Initialize the policy enforcer with sample policies
    policy_enforcer = PolicyEnforcer()
    
    # In a real application, you would load policies from files:
    # policy_enforcer = PolicyEnforcer(policy_dir="/path/to/policies")
    
    # Create and start the endpoint monitor
    monitor = EndpointMonitor(policy_enforcer=policy_enforcer)
    
    # Register our callback for activity notifications
    monitor.register_callback(activity_callback)
    
    try:
        # Start monitoring
        monitor.start()
        logger.info("Monitoring endpoint activities. Press Ctrl+C to stop...")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Stopping endpoint monitoring...")
    
    finally:
        # Stop monitoring
        monitor.stop()
        logger.info("Endpoint monitoring stopped")

if __name__ == "__main__":
    main()
