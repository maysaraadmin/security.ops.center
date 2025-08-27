"""
Test script for Sysmon Collector
"""
import json
import logging
import sys
import time
from datetime import datetime, timedelta

# Add the src directory to the path
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.siem.collectors.sysmon_collector import SysmonCollector, collect_sysmon_events  # noqa: E402

def setup_logging():
    """Configure logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('sysmon_test.log', encoding='utf-8')
        ]
    )

class TestSysmonCollector:
    """Test cases for Sysmon Collector."""
    
    def test_initialization(self):
        """Test that the collector initializes correctly."""
        collector = SysmonCollector()
        try:
            assert collector is not None
            assert 'sysmon' in collector.handles
        finally:
            collector.close()
        
    def test_collect_events(self):
        """Test collecting events."""
        collector = SysmonCollector()
        try:
            # Get recent events
            events = collector.get_events(limit=5)
            assert isinstance(events, list)
            
            if events:  # If there are events to check
                event = events[0]
                assert 'event_id' in event
                assert 'timestamp' in event
                assert 'source' in event
                assert event['source'] == 'sysmon'
        finally:
            collector.close()
    
    def test_collect_sysmon_events_function(self):
        """Test the convenience function."""
        events = collect_sysmon_events()
        assert isinstance(events, list)

def generate_test_event(event_type=1):
    """
    Generate a test Sysmon event.
    
    Args:
        event_type: The type of Sysmon event to generate
        
    Returns:
        Dictionary containing test event data
    """
    now = datetime.utcnow()
    return {
        'event_id': event_type,
        'timestamp': now.isoformat(),
        'source': 'sysmon',
        'computer_name': 'TEST-PC',
        'process_id': 1234,
        'thread_id': 5678,
        'level': 'info',
        'event_data': {
            'RuleName': 'Test Rule',
            'UtcTime': now.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'ProcessGuid': 'TEST-GUID',
            'ProcessId': '1234',
            'Image': 'C:\\test\\test.exe',
            'CommandLine': 'test.exe --test-arg',
            'User': 'TEST-PC\\testuser'
        }
    }

def run_tests():
    """Run all tests and print results."""
    setup_logging()
    logger = logging.getLogger(__name__)
    test = TestSysmonCollector()
    
    tests = [
        ('test_initialization', test.test_initialization),
        ('test_collect_events', test.test_collect_events),
        ('test_collect_sysmon_events_function', test.test_collect_sysmon_events_function)
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            test_func()
            results[name] = 'PASSED'
            logger.info("%s: PASSED", name)
        except Exception as e:
            results[name] = f'FAILED: {str(e)}'
            logger.error("%s: FAILED - %s", name, str(e))
    
    # Print summary
    print("\nTest Results:" + "="*50)
    for name, result in results.items():
        print(f"{name}: {result}")
    
    # Generate a test event for demonstration
    print("\nSample Test Event:" + "="*50)
    test_event = generate_test_event()
    print(json.dumps(test_event, indent=2))

if __name__ == "__main__":
    run_tests()
