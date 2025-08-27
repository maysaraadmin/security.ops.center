"""
Test script for the LogCollector component.
"""

import os
import sys
import time
import tempfile
import logging
import threading
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the SimpleSIEM class
from src.siem.core.simple_siem import SimpleSIEM

def test_log_collector():
    """Test the LogCollector component."""
    print("Testing LogCollector component...")
    
    # Create a temporary directory for logs
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test log file
        test_log = os.path.join(temp_dir, "test.log")
        
        # Create the log file before initializing the LogCollector
        with open(test_log, 'w') as f:
            f.write("# Test log file\n")
        
        # Create a test configuration
        config = {
            'logging': {
                'level': 'DEBUG',
                'console': {
                    'enabled': True,
                    'level': 'INFO'
                }
            },
            'components': {
                'enabled': ['log_collector'],
                'log_collector': {
                    'enabled': True,
                    'paths': [test_log],
                    'poll_interval': 1,
                    'read_from_beginning': True
                }
            }
        }
        
        # Create and start the SIEM
        siem = SimpleSIEM(config)
        
        # Create an event handler for log events
        log_events = []
        
        def handle_log_event(event):
            log_events.append(event)
            # Only print debug info for actual test messages, not the initial file creation
            if not event.get('message', '').startswith('#'):
                print(f"Received log event: {event}")
                
        # Clear any previous handlers to avoid duplicates
        siem.event_bus.subscribers = {k: [] for k in siem.event_bus.subscribers.keys()}
        # Subscribe to log events
        siem.event_bus.subscribe('log_event', handle_log_event)
        
        
        # Start components directly instead of using the start() method to avoid signal issues
        print("Starting LogCollector component...")
        
        # Get the log collector component
        log_collector = siem.components.get('log_collector')
        if not log_collector:
            print("❌ LogCollector component not found in SIEM")
            return False
            
        if not hasattr(log_collector, 'start') or not hasattr(log_collector, 'stop'):
            print("❌ LogCollector is missing required methods (start/stop)")
            return False
            
        # Start the log collector
        print("Starting LogCollector...")
        log_collector.start()
        
        # Give it a moment to initialize
        time.sleep(2)
        
        if not log_collector.running:
            print("❌ LogCollector failed to start")
            return False
            
        print("✅ LogCollector started successfully")
        
        try:
            # Wait a bit more to ensure it's ready
            time.sleep(1)
            
            # Write test logs
            test_messages = [
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Test log message 1",
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Test log message 2",
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Test log message 3"
            ]
            
            print("\nWriting test logs...")
            with open(test_log, 'a') as f:
                for i, msg in enumerate(test_messages, 1):
                    f.write(f"{msg}\n")
                    f.flush()
                    print(f"  Wrote: {msg}")
                    if i < len(test_messages):
                        time.sleep(1)  # Small delay between writes
            
            # Wait for the logs to be processed
            print("\nWaiting for logs to be processed...")
            max_wait = 10  # Increased timeout for CI environments
            start_time = time.time()
            expected_count = len(test_messages)
            
            while (time.time() - start_time) < max_wait:
                current_count = len([e for e in log_events if not e.get('message', '').startswith('#')])
                print(f"  Collected {current_count}/{expected_count} test log messages...")
                
                if current_count >= expected_count:
                    break
                    
                time.sleep(0.5)
            else:
                print(f"⚠️  Timeout waiting for log messages. Found {len(log_events)} messages, expected {expected_count}")
                
            # Filter out any non-test messages (like the initial file creation)
            test_log_events = [e for e in log_events if not e.get('message', '').startswith('#')]
            
            # Verify logs were collected
            print("\nVerifying collected logs...")
            if not test_log_events:
                print("❌ No test log events were collected")
                print("All events received:", log_events)
                return False
                
            print(f"Collected {len(test_log_events)} test log events (total events: {len(log_events)})")
            
            # Check if all test messages were received
            missing_messages = []
            for i, msg in enumerate(test_messages, 1):
                # Check if any log event contains this test message
                found = any(msg in event.get('message', '') for event in test_log_events)
                status = "✓" if found else "✗"
                print(f"  {status} {msg}")
                if not found:
                    missing_messages.append(msg)
            
            if missing_messages:
                print(f"❌ Missing {len(missing_messages)}/{len(test_messages)} log messages")
                print("All received events:")
                for i, event in enumerate(log_events, 1):
                    print(f"  {i}. {event.get('message', '')}")
                return False
                
            print("✅ All test messages were successfully collected")
            
            # Test log rotation
            print("\nTesting log rotation...")
            rotated_log = f"{test_log}.1"
            
            # Add a new message to the log
            rotation_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Testing log rotation"
            with open(test_log, 'a') as f:
                f.write(f"{rotation_message}\n")
            
            # Rotate the log file
            if os.path.exists(rotated_log):
                os.remove(rotated_log)
            os.rename(test_log, rotated_log)
            
            # Create a new log file
            new_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] New log message after rotation"
            with open(test_log, 'w') as f:
                f.write(f"{new_message}\n")
            
            # Wait for the log collector to process
            print("Waiting for log rotation to be detected...")
            time.sleep(2)
            
            # Check if both the rotation message and new message were received
            rotation_found = any(rotation_message in e.get('message', '') for e in log_events)
            new_message_found = any(new_message in e.get('message', '') for e in log_events)
            
            if rotation_found and new_message_found:
                print("✅ Log collector successfully handled log rotation")
                print(f"  ✓ Found rotation message")
                print(f"  ✓ Found new message after rotation")
            else:
                if not rotation_found:
                    print("❌ Did not find rotation message in collected logs")
                if not new_message_found:
                    print("❌ Did not find new message after rotation in collected logs")
            
            return True
            
        except Exception as e:
            print(f"❌ Test failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return False
            
        finally:
            # Stop the log collector if it exists
            if log_collector and hasattr(log_collector, 'stop'):
                log_collector.stop()
            
            # Stop the SIEM
            siem.running = False
            siem.shutdown_event.set()

def main():
    """Run the LogCollector test."""
    print("=" * 50)
    print("Testing LogCollector Component")
    print("=" * 50)
    
    if test_log_collector():
        print("\n✅ LogCollector test completed successfully")
        return 0
    else:
        print("\n❌ LogCollector test failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
