"""
Test Suite for SIEM Core Functionality

This module contains tests for the core components of the SIEM system.
"""

import os
import sys
import time
import json
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.siem import SIEM, EventBus
from src.core.alert_manager import AlertManager, Alert, AlertSeverity, AlertStatus
from src.core.log_collector import LogCollector, LogNormalizer
from src.core.utils import get_file_hash, is_valid_ip, is_private_ip

class TestSIEMCore(unittest.TestCase):
    """Test cases for the SIEM core functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.config = {
            'global': {
                'log_level': 'INFO'
            },
            'log_collection': {
                'enabled': True
            },
            'correlation': {
                'enabled': True
            },
            'alerting': {
                'enabled': True
            },
            'modules': {
                'edr': {'enabled': True},
                'ndr': {'enabled': True},
                'dlp': {'enabled': True},
                'fim': {'enabled': True},
                'hips': {'enabled': True},
                'nips': {'enabled': True},
                'compliance': {'enabled': True}
            },
            'storage': {
                'type': 'memory'
            }
        }
        
        # Create a test log file
        self.test_log_file = os.path.join(self.test_dir, 'test.log')
        with open(self.test_log_file, 'w') as f:
            f.write('Test log entry 1\n')
            f.write('Test log entry 2\n')
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_siem_initialization(self):
        """Test SIEM initialization with default config."""
        with patch('core.log_collector.LogCollector'), \
             patch('core.correlation_engine.CorrelationEngine'), \
             patch('edr.server.EDRAgentServer'), \
             patch('ndr.manager.NDRManager'), \
             patch('dlp.manager.DLPManager'), \
             patch('fim.manager.FIMManager'), \
             patch('hips.manager.HIPSManager'), \
             patch('nips.manager.NIPSManager'), \
             patch('compliance.manager.ComplianceManager'):
            
            siem = SIEM(self.config)
            self.assertIsNotNone(siem)
            self.assertIsNotNone(siem.event_bus)
    
    def test_event_bus_pub_sub(self):
        """Test event bus publish/subscribe functionality."""
        event_bus = EventBus()
        test_events = []
        
        def event_handler(event):
            test_events.append(event)
        
        # Subscribe to test event
        event_bus.subscribe('test_event', event_handler)
        
        # Publish an event
        test_event = {'type': 'test', 'data': 'test data'}
        event_bus.publish('test_event', test_event)
        
        # Check if handler was called
        self.assertEqual(len(test_events), 1)
        self.assertEqual(test_events[0], test_event)
    
    def test_alert_manager_alert_creation(self):
        """Test alert creation and retrieval."""
        alert_manager = AlertManager()
        
        # Create a test alert
        alert = alert_manager.create_alert(
            title="Test Alert",
            description="This is a test alert",
            severity=AlertSeverity.HIGH,
            source="test"
        )
        
        # Verify alert was created
        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, "Test Alert")
        self.assertEqual(alert.status, AlertStatus.NEW)
        
        # Retrieve the alert
        retrieved_alert = alert_manager.get_alert(alert.id)
        self.assertEqual(alert.id, retrieved_alert.id)
    
    def test_log_normalization(self):
        """Test log normalization with different log formats."""
        normalizer = LogNormalizer()
        
        # Test syslog format
        syslog = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        normalized = normalizer.normalize(syslog, 'syslog')
        self.assertEqual(normalized['source'], 'mymachine')
        self.assertEqual(normalized['severity'], 'crit')
        
        # Test JSON format
        json_log = '{"@timestamp":"2023-01-01T12:00:00Z","message":"Test message","level":"error"}'
        normalized = normalizer.normalize(json_log, 'json')
        self.assertEqual(normalized['severity'], 'err')
        self.assertEqual(normalized['message'], 'Test message')
    
    @patch('core.log_collector.Observer')
    def test_log_collector_file_monitoring(self, mock_observer):
        """Test log collector file monitoring."""
        # Set up test log file
        test_log = os.path.join(self.test_dir, 'test_monitor.log')
        with open(test_log, 'w') as f:
            f.write('Initial log line\n')
        
        # Initialize log collector
        collector = LogCollector()
        
        # Add test log file
        collector.add_source('file', test_log)
        
        # Start monitoring
        collector.start()
        
        # Add a new log line
        with open(test_log, 'a') as f:
            f.write('New log line\n')
        
        # Simulate file system event
        collector._on_modified(test_log)
        
        # Check if observer was started
        mock_observer.return_value.start.assert_called_once()
    
    def test_utils_functions(self):
        """Test utility functions."""
        # Test IP validation
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertFalse(is_valid_ip('not.an.ip'))
        
        # Test private IP detection
        self.assertTrue(is_private_ip('192.168.1.1'))
        self.assertFalse(is_private_ip('8.8.8.8'))
        
        # Test file hashing
        test_file = os.path.join(self.test_dir, 'test_hash.txt')
        with open(test_file, 'w') as f:
            f.write('test content')
        
        file_hash = get_file_hash(test_file)
        self.assertEqual(len(file_hash), 64)  # SHA-256 hash length

if __name__ == '__main__':
    unittest.main()
