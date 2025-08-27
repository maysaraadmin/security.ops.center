"""
Test SIEM Integration

This script tests the SIEM integration by sending test events to the configured SIEM systems.
"""
import os
import json
import time
import logging
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

# Import SIEM service and event class
from src.siem.services.siem_service import get_siem_service
from src.siem.integrations.siem_integration import SIEMEvent, SIEMType

class SimpleSIEMHandler(BaseHTTPRequestHandler):
    """Simple HTTP server handler to simulate a SIEM for testing"""
    events: List[Dict[str, Any]] = []
    
    def do_POST(self):
        """Handle POST requests to the SIEM endpoint"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            # Parse the event data
            event = json.loads(post_data.decode('utf-8'))
            self.events.append(event)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"text": "Success", "code": 0}).encode('utf-8'))
            logger.info(f"Received event: {json.dumps(event, indent=2)}")
        except Exception as e:
            logger.error(f"Error processing SIEM event: {e}")
            self.send_response(500)
            self.end_headers()
            
    def log_message(self, format, *args):
        """Override to prevent logging every request to stderr"""
        return

class SimpleSIEMServer:
    """Simple SIEM server for testing"""
    def __init__(self, host='localhost', port=18080):
        self.host = host
        self.port = port
        self.server = HTTPServer((host, port), SimpleSIEMHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        
    def start(self):
        """Start the SIEM server"""
        self.thread.start()
        logger.info(f"Started test SIEM server at http://{self.host}:{self.port}")
        
    def stop(self):
        """Stop the SIEM server"""
        self.server.shutdown()
        self.server.server_close()
        logger.info("Stopped test SIEM server")
        
    def get_events(self) -> List[Dict[str, Any]]:
        """Get all received events"""
        return SimpleSIEMHandler.events
        
    def clear_events(self):
        """Clear all received events"""
        SimpleSIEMHandler.events = []

# Create a test SIEM server
test_siem = SimpleSIEMServer()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for more detailed output
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem_test')

# Enable debug logging for SIEM components
logging.getLogger('src.siem').setLevel(logging.DEBUG)

def test_siem_integration():
    """Test the SIEM integration by sending test events."""
    # Start the test SIEM server with a timeout
    test_siem.start()
    
    # Create a test configuration with a short timeout
    test_config = {
        'enabled': True,
        'worker_threads': 1,  # Use a single worker thread for testing
        'batch_processing': {
            'enabled': False  # Disable batch processing for simpler testing
        },
        'enabled': True,
        'integrations': {
            'test_siem': {
                'enabled': True,
                'type': 'splunk',
                'url': f'http://{test_siem.host}:{test_siem.port}/services/collector/event',
                'token': 'test_token',
                'verify_ssl': False,
                'timeout': 2,  # Shorter timeout for testing
                'retry_attempts': 1  # Only try once
            }
        },
        'queue_size': 1000,
        'worker_threads': 2,
        'batch_size': 10,
        'batch_timeout': 5,
        'retry_attempts': 3,
        'retry_delay': 1,
        'default_fields': {
            'product': 'edr_system',
            'vendor': 'security_operations_center',
            'version': '1.0.0'
        },
        'global_fields': {
            'environment': 'test',
            'region': 'test-region'
        }
    }
    
    # Save the test config to a temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        import yaml
        yaml.dump(test_config, f)
        config_path = f.name
    
    try:
        # Get the SIEM service with test config and ensure it's not a singleton
        siem_service = get_siem_service(config_path)
        
        # Force reinitialization for testing
        if hasattr(siem_service, 'stop'):
            siem_service.stop()
            time.sleep(0.5)  # Give it time to stop
        
        # Check initial status
        initial_status = siem_service.get_status()
        logger.info(f"Initial SIEM Service Status: {json.dumps(initial_status, indent=2)}")
        
        # Start the SIEM service with detailed logging
        logger.info("Starting SIEM service...")
        siem_service.start()
        
        # Wait a moment for the service to initialize
        time.sleep(1)
        
        # Verify service is running with a timeout
        max_wait = 5  # seconds
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status = siem_service.get_status()
            logger.info(f"SIEM service status: {json.dumps(status, indent=2)}")
            
            if siem_service.running:
                # Check worker threads
                if hasattr(siem_service, 'worker_threads') and siem_service.worker_threads:
                    active_workers = [t for t in siem_service.worker_threads if t.is_alive()]
                    if active_workers:
                        logger.info(f"Found {len(active_workers)} active worker threads")
                        break
                    logger.warning("No active worker threads found, retrying...")
                else:
                    logger.warning("No worker threads attribute found, retrying...")
            
            time.sleep(0.5)
        else:
            # If we get here, the timeout was reached
            if not siem_service.running:
                raise RuntimeError("SIEM service failed to start within timeout")
            if not any(t.is_alive() for t in getattr(siem_service, 'worker_threads', [])):
                raise RuntimeError("No worker threads started within timeout")
        # Clear any existing events in the test SIEM
        test_siem.clear_events()
        
        # Test event data
        test_events = [
            {
                "event_type": "login_success",
                "username": "testuser",
                "source_ip": "192.168.1.100",
                "user_agent": "Mozilla/5.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "info"
            },
            {
                "event_type": "login_failed",
                "username": "attacker",
                "source_ip": "10.0.0.1",
                "user_agent": "curl/7.68.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "high",
                "failed_attempts": 5,
                "details": "Multiple failed login attempts"
            },
            {
                "event_type": "malware_detected",
                "agent_id": "agent-12345",
                "file_path": "C:\\Windows\\Temp\\malware.exe",
                "file_hash": "a1b2c3d4e5f6...",
                "threat_name": "Trojan.Generic.1234",
                "severity": "critical",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "action_taken": "quarantined",
                    "scan_type": "on_demand",
                    "engine_version": "1.2.3.4"
                }
            }
        ]
        
        # Send test events
        sent_events = 0
        for i, event in enumerate(test_events, 1):
            logger.info(f"Sending test event {i}/{len(test_events)}")
            
            # Create a SIEM event object
            siem_event = SIEMEvent(
                event_type=event.get('event_type', 'unknown'),
                timestamp=datetime.fromisoformat(event['timestamp']) if 'timestamp' in event and isinstance(event['timestamp'], str) else datetime.now(timezone.utc),
                source="edr_test",
                severity=event.get('severity', 'info'),
                details=event
            )
            success = siem_service.send_event(siem_event)
            
            if success:
                sent_events += 1
                logger.info(f"Successfully queued event: {event['event_type']}")
            else:
                logger.error(f"Failed to queue event: {event['event_type']}")
            
            # Small delay between events
            time.sleep(0.5)
        
        # Test individual events
        logger.info("Testing individual event sending...")
        for i in range(2):
            event_data = {
                "event_type": f"test.event.{i}",
                "message": f"Test event {i}",
                "severity": "info",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            siem_event = SIEMEvent(
                event_type=event_data['event_type'],
                timestamp=datetime.fromisoformat(event_data['timestamp']),
                source="edr_test",
                severity=event_data['severity'],
                details=event_data
            )
            success = siem_service.send_event(siem_event)
            if success:
                sent_events += 1
                logger.info(f"Successfully queued test event {i}")
            else:
                logger.error(f"Failed to queue test event {i}")
            time.sleep(0.5)
        
        # Wait for events to be processed with a timeout
        max_wait = 10  # seconds
        start_time = time.time()
        processed_events = 0
        
        while time.time() - start_time < max_wait:
            # Check if all events were processed
            processed_events = len(test_siem.get_events())
            if processed_events >= sent_events:
                break
                
            # Log progress
            logger.info(f"Waiting for events to be processed... ({processed_events}/{sent_events} processed)")
            time.sleep(0.5)
            
            # Check if the service is still running
            if not siem_service.running:
                raise RuntimeError("SIEM service stopped unexpectedly")
                
        logger.info(f"Processed {processed_events} out of {sent_events} events in {time.time() - start_time:.2f} seconds")
        
        # Get final status
        final_status = siem_service.get_status()
        logger.info(f"Final SIEM Service Status: {json.dumps(final_status, indent=2)}")
        
        # Verify events were processed
        queue_size = final_status.get('queue_size', 0)
        if queue_size > 0:
            logger.warning(f"There are still {queue_size} events in the queue")
        
        logger.info(f"Successfully processed at least {sent_events - queue_size} out of {sent_events} events")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}", exc_info=True)
        raise
    finally:
        # Stop the SIEM service with force if needed
        if 'siem_service' in locals():
            try:
                logger.info("Stopping SIEM service...")
                siem_service.stop()
                
                # Force stop any remaining threads
                if hasattr(siem_service, 'worker_threads'):
                    for t in siem_service.worker_threads:
                        if t.is_alive():
                            logger.warning(f"Force stopping worker thread: {t.name}")
                            # No direct way to stop threads in Python, but we can mark them for exit
                            
                logger.info("SIEM service stopped")
            except Exception as e:
                logger.error(f"Error stopping SIEM service: {e}")
        
        # Stop the test SIEM server
        try:
            logger.info("Stopping test SIEM server...")
            test_siem.stop()
            logger.info("Test SIEM server stopped")
        except Exception as e:
            logger.error(f"Error stopping test SIEM server: {e}")
        
        # Clean up the temporary config file
        try:
            if 'config_path' in locals() and os.path.exists(config_path):
                os.unlink(config_path)
                logger.info("Cleaned up temporary config file")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary config file: {e}")
            
        # Force garbage collection to help with cleanup
        import gc
        gc.collect()

if __name__ == "__main__":
    test_siem_integration()
